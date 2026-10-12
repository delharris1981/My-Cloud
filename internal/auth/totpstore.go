package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/derek/my-cloud/internal/crypt"
)

// ErrTOTPNotEnrolled means the user has no confirmed second factor.
var ErrTOTPNotEnrolled = errors.New("totp not enrolled")

// TOTPStore persists enrolment state, sealing secrets with the secrets subkey
// so they are encrypted at rest rather than the plaintext base32 the Node
// version kept in JSON.
type TOTPStore struct {
	db     *sql.DB
	sealer *crypt.Sealer
}

// NewTOTPStore wires the store.
func NewTOTPStore(db *sql.DB, sealer *crypt.Sealer) *TOTPStore {
	return &TOTPStore{db: db, sealer: sealer}
}

// aad binds a sealed TOTP blob to this user, so it cannot be transplanted.
func totpAAD(username string) string { return "totp:" + username }

// BeginSetup generates a pending secret and returns it plus the enrolment URI.
// Nothing is active until Confirm succeeds, so a half-finished enrolment never
// locks anyone out.
//
// The secret column is NOT NULL, so a staged enrolment is held in a row with
// enabled=0 and no active secret; Confirm promotes it. An existing enrolment is
// cleared rather than half-overwritten: restarting setup must not leave a
// working second factor in an indeterminate state.
func (t *TOTPStore) BeginSetup(ctx context.Context, username, siteName string) (secret, uri string, err error) {
	username = NormaliseUsername(username)
	secret, err = GenerateTOTPSecret()
	if err != nil {
		return "", "", err
	}
	sealed, err := t.sealer.SealString(crypt.PurposeSecrets, totpAAD(username), secret)
	if err != nil {
		return "", "", fmt.Errorf("auth: seal pending totp: %w", err)
	}
	// Replace any existing row: a staged enrolment is the only state here.
	if _, err := t.db.ExecContext(ctx,
		`DELETE FROM totp WHERE username=?`, username); err != nil {
		return "", "", fmt.Errorf("auth: clear totp: %w", err)
	}
	// The pending secret lives in the pending column. The active secret column
	// gets a sealed empty string: a well-formed placeholder that satisfies
	// NOT NULL without being usable as a secret. Confirm overwrites it.
	sealedEmpty, err := t.sealer.SealString(crypt.PurposeSecrets, totpAAD(username), "")
	if err != nil {
		return "", "", fmt.Errorf("auth: seal empty totp: %w", err)
	}
	if _, err := t.db.ExecContext(ctx,
		`INSERT INTO totp(username, secret, pending, enabled, created_at)
		 VALUES(?, ?, ?, 0, ?)`,
		username, sealedEmpty, sealed, time.Now().UnixMilli()); err != nil {
		return "", "", fmt.Errorf("auth: stage totp: %w", err)
	}
	if siteName == "" {
		siteName = "My Cloud"
	}
	return secret, TOTPURI(secret, username, siteName), nil
}

// Confirm promotes the pending secret to active and returns recovery codes,
// shown once. The caller must display them; they are not retrievable after.
func (t *TOTPStore) Confirm(ctx context.Context, username, code string) ([]string, error) {
	username = NormaliseUsername(username)
	var sealedPending []byte
	err := t.db.QueryRowContext(ctx, `SELECT pending FROM totp WHERE username=?`, username).Scan(&sealedPending)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("start two-factor setup first")
		}
		return nil, err
	}
	if len(sealedPending) == 0 {
		return nil, errors.New("start two-factor setup first")
	}
	pending, err := t.sealer.OpenString(crypt.PurposeSecrets, totpAAD(username), sealedPending)
	if err != nil {
		return nil, fmt.Errorf("auth: open pending totp: %w", err)
	}
	if !VerifyTOTP(pending, code, time.Now()) {
		return nil, errors.New("that code is incorrect, try again")
	}

	// Re-seal under the confirmed AAD (same AAD, fresh nonce) and mark active.
	sealed, err := t.sealer.SealString(crypt.PurposeSecrets, totpAAD(username), pending)
	if err != nil {
		return nil, fmt.Errorf("auth: seal totp: %w", err)
	}
	if _, err := t.db.ExecContext(ctx,
		`UPDATE totp SET secret=?, pending=NULL, enabled=1 WHERE username=?`, sealed, username); err != nil {
		return nil, fmt.Errorf("auth: confirm totp: %w", err)
	}

	codes, err := t.resetRecoveryCodes(ctx, username)
	if err != nil {
		return nil, err
	}
	return codes, nil
}

// resetRecoveryCodes replaces the user's recovery codes and returns the
// plaintext set for one-time display.
func (t *TOTPStore) resetRecoveryCodes(ctx context.Context, username string) ([]string, error) {
	if _, err := t.db.ExecContext(ctx, `DELETE FROM recovery_codes WHERE username=?`, username); err != nil {
		return nil, err
	}
	codes := make([]string, 0, 10)
	for i := 0; i < 10; i++ {
		c, err := randomHex(5) // 10 hex chars, matching the Node format
		if err != nil {
			return nil, err
		}
		hash, err := HashRecoveryCode(c)
		if err != nil {
			return nil, err
		}
		if _, err := t.db.ExecContext(ctx,
			`INSERT INTO recovery_codes(username, code_hash) VALUES(?,?)`, username, hash); err != nil {
			return nil, fmt.Errorf("auth: store recovery code: %w", err)
		}
		codes = append(codes, c)
	}
	return codes, nil
}

// Verify checks a second factor: a TOTP code, or a recovery code (which is
// consumed on use).
func (t *TOTPStore) Verify(ctx context.Context, username, code string) bool {
	username = NormaliseUsername(username)
	var sealed []byte
	var enabled int
	err := t.db.QueryRowContext(ctx, `SELECT secret, enabled FROM totp WHERE username=?`, username).
		Scan(&sealed, &enabled)
	if err != nil || enabled != 1 || len(sealed) == 0 {
		return false
	}
	secret, err := t.sealer.OpenString(crypt.PurposeSecrets, totpAAD(username), sealed)
	if err != nil {
		// A key mismatch means the secret cannot be checked; fail closed
		// rather than allowing the second factor to be skipped.
		return false
	}
	if VerifyTOTP(secret, code, time.Now()) {
		return true
	}
	return t.consumeRecoveryCode(ctx, username, code)
}

// consumeRecoveryCode verifies a recovery code and burns it. Codes are
// single-use: the row's used_at is stamped and it is never valid again.
func (t *TOTPStore) consumeRecoveryCode(ctx context.Context, username, code string) bool {
	clean := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(code), " ", ""))
	if clean == "" {
		return false
	}
	// Read every hash and close the cursor before the write below: an open
	// cursor holds the single pooled connection, so a write issued while it
	// is live would deadlock.
	rows, err := t.db.QueryContext(ctx,
		`SELECT code_hash FROM recovery_codes WHERE username=? AND used_at IS NULL`, username)
	if err != nil {
		return false
	}
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err == nil {
			hashes = append(hashes, h)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false
	}

	for _, h := range hashes {
		if CompareRecoveryCode(h, clean) {
			// Stamp used_at so the code cannot be replayed. The row is kept
			// for audit rather than deleted.
			_, _ = t.db.ExecContext(ctx,
				`UPDATE recovery_codes SET used_at=? WHERE username=? AND code_hash=?`,
				time.Now().UnixMilli(), username, h)
			return true
		}
	}
	return false
}

// Enabled reports whether a second factor is active for the user.
func (t *TOTPStore) Enabled(ctx context.Context, username string) bool {
	var enabled int
	err := t.db.QueryRowContext(ctx, `SELECT enabled FROM totp WHERE username=?`, NormaliseUsername(username)).Scan(&enabled)
	return err == nil && enabled == 1
}

// Disable removes the second factor and its recovery codes.
func (t *TOTPStore) Disable(ctx context.Context, username string) error {
	_, err := t.db.ExecContext(ctx, `DELETE FROM totp WHERE username=?`, NormaliseUsername(username))
	if err != nil {
		return err
	}
	_, err = t.db.ExecContext(ctx, `DELETE FROM recovery_codes WHERE username=?`, NormaliseUsername(username))
	return err
}
