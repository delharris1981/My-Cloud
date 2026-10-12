package auth

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/derek/my-cloud/internal/crypt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// PasskeyStore persists WebAuthn credentials.
//
// Credential IDs and public keys are sealed with the passkeys subkey: both are
// material an attacker could otherwise use offline, and the root key already
// exists as the project's encryption root.
type PasskeyStore struct {
	db     *sql.DB
	sealer *crypt.Sealer
}

// NewPasskeyStore wires the store.
func NewPasskeyStore(db *sql.DB, sealer *crypt.Sealer) *PasskeyStore {
	return &PasskeyStore{db: db, sealer: sealer}
}

// WebAuthnUser adapts a username to the library's User interface.
type WebAuthnUser struct {
	Username string
	// ID is the user handle. Derived from the username so it is stable across
	// restarts without needing a separate column.
	ID []byte

	// credentials holds the user's registered passkeys, decrypted. It is
	// unexported so nothing can accidentally read the raw material off the
	// struct, and handed to the ceremony through WithUserCredentials.
	credentials []webauthn.Credential
}

// WithUserCredentials attaches the registered credentials to the user handle
// the ceremony consumes.
func (u WebAuthnUser) WithUserCredentials() WebAuthnUserWithCredentials {
	return WebAuthnUserWithCredentials{WebAuthnUser: u, creds: u.credentials}
}

// WebAuthnUserWithCredentials is a WebAuthnUser carrying its credentials.
type WebAuthnUserWithCredentials struct {
	WebAuthnUser
	creds []webauthn.Credential
}

// WebAuthnCredentials returns the decrypted credentials.
func (u WebAuthnUserWithCredentials) WebAuthnCredentials() []webauthn.Credential {
	return u.creds
}

// WebAuthnID returns the opaque user handle. It must be stable for a given
// account: changing it invalidates every registered passkey.
func (u WebAuthnUser) WebAuthnID() []byte { return u.ID }

// WebAuthnName is the display name shown by the authenticator.
func (u WebAuthnUser) WebAuthnName() string { return u.Username }

// WebAuthnDisplayName is the human-readable name.
func (u WebAuthnUser) WebAuthnDisplayName() string { return u.Username }

// WebAuthnCredentials returns the registered credentials. The plain user has
// none; a login ceremony uses WebAuthnUserWithCredentials instead.
func (u WebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return nil }

// Credentials exposes the decrypted credential count so callers can tell an
// account with no passkeys from one that simply has not loaded them yet.
func (u WebAuthnUser) Credentials() []webauthn.Credential { return u.credentials }

// UserHandle derives the stable user handle for a username.
func UserHandle(username string) []byte {
	sum := sha256.Sum256([]byte("mycloud:webauthn:" + NormaliseUsername(username)))
	return sum[:]
}

// ErrNoPasskey means no credential matched the presented ID.
var ErrNoPasskey = errors.New("no such passkey")

// passkeyAAD binds a sealed credential to its user, so a credential cannot be
// moved to another account.
func passkeyAAD(username string) string { return "passkey:" + NormaliseUsername(username) }

// Save stores a newly registered credential.
func (s *PasskeyStore) Save(ctx context.Context, username string, cred *webauthn.Credential, label string) error {
	id, err := s.sealer.Seal(crypt.PurposePasskeys, passkeyAAD(username), cred.ID)
	if err != nil {
		return fmt.Errorf("auth: seal credential id: %w", err)
	}
	pk, err := s.sealer.Seal(crypt.PurposePasskeys, passkeyAAD(username), cred.PublicKey)
	if err != nil {
		return fmt.Errorf("auth: seal public key: %w", err)
	}
	var aaguid []byte
	if cred.Authenticator.AAGUID != nil {
		aaguid = cred.Authenticator.AAGUID
	}
	transports := ""
	if len(cred.Transport) > 0 {
		b, _ := json.Marshal(cred.Transport)
		transports = string(b)
	}
	uv := 0
	if cred.Flags.UserVerified {
		uv = 1
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO passkeys(credential_id, username, public_key, sign_count, aaguid, transports,
		                       backed_up, uv, created_at, label)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		id, NormaliseUsername(username), pk, cred.Authenticator.SignCount, aaguid,
		nullIfEmpty(transports), boolInt(cred.Flags.BackupEligible && cred.Flags.BackupState),
		uv, time.Now().UnixMilli(), nullIfEmpty(label)); err != nil {
		return fmt.Errorf("auth: insert passkey: %w", err)
	}
	return nil
}

// LoadUser returns the username's credentials, decrypted, ready for a login
// ceremony.
func (s *PasskeyStore) LoadUser(ctx context.Context, username string) (WebAuthnUser, error) {
	username = NormaliseUsername(username)
	u := WebAuthnUser{Username: username, ID: UserHandle(username)}
	rows, err := s.db.QueryContext(ctx,
		`SELECT credential_id, public_key, sign_count, aaguid, transports, backed_up, uv
		 FROM passkeys WHERE username=?`, username)
	if err != nil {
		return u, err
	}
	defer rows.Close()
	var creds []webauthn.Credential
	for rows.Next() {
		var sealedID, sealedPK []byte
		var signCount int
		var aaguid []byte
		var transports sql.NullString
		var backedUp, uv int
		if err := rows.Scan(&sealedID, &sealedPK, &signCount, &aaguid, &transports, &backedUp, &uv); err != nil {
			return u, err
		}
		id, err := s.sealer.Open(crypt.PurposePasskeys, passkeyAAD(username), sealedID)
		if err != nil {
			continue // a credential we cannot decrypt is unusable
		}
		pk, err := s.sealer.Open(crypt.PurposePasskeys, passkeyAAD(username), sealedPK)
		if err != nil {
			continue
		}
		c := webauthn.Credential{
			ID:              id,
			PublicKey:       pk,
			AttestationType: "",
			Transport:       []protocol.AuthenticatorTransport{},
		}
		if transports.Valid && transports.String != "" {
			json.Unmarshal([]byte(transports.String), &c.Transport)
		}
		c.Authenticator.SignCount = uint32(signCount)
		if len(aaguid) > 0 {
			c.Authenticator.AAGUID = aaguid
		}
		c.Flags.BackupEligible = backedUp == 1
		c.Flags.BackupState = backedUp == 1
		c.Flags.UserVerified = uv == 1
		creds = append(creds, c)
	}
	if err := rows.Err(); err != nil {
		return u, err
	}
	if creds == nil {
		creds = []webauthn.Credential{}
	}
	u.credentials = creds
	return u, nil
}

// UpdateSignCount persists the counter after a successful assertion.
//
// go-webauthn rejects a non-increasing counter as the cloned-authenticator
// signal, so persisting it is what makes that check work across restarts.
// A counter that fails to advance is common on some platforms, so the library's
// own judgement is respected rather than second-guessed here.
//
// The row is matched on username plus the *decrypted* credential id rather than
// on the sealed blob: every Seal call draws a fresh nonce, so re-sealing an id
// produces different bytes and would never match the stored row.
func (s *PasskeyStore) UpdateSignCount(ctx context.Context, username string, cred *webauthn.Credential) error {
	username = NormaliseUsername(username)

	// Walk the stored rows, decrypting each id to find the match. A user has
	// only a handful of passkeys, so this is cheaper than it looks.
	rows, err := s.db.QueryContext(ctx,
		`SELECT credential_id FROM passkeys WHERE username=?`, username)
	if err != nil {
		return err
	}
	var target []byte
	for rows.Next() {
		var sealed []byte
		if err := rows.Scan(&sealed); err != nil {
			rows.Close()
			return err
		}
		opened, err := s.sealer.Open(crypt.PurposePasskeys, passkeyAAD(username), sealed)
		if err != nil {
			continue
		}
		if string(opened) == string(cred.ID) {
			target = sealed
			break
		}
	}
	rows.Close()
	if target == nil {
		return ErrNoPasskey
	}

	_, err = s.db.ExecContext(ctx,
		`UPDATE passkeys SET sign_count=?, last_used=? WHERE credential_id=? AND username=?`,
		cred.Authenticator.SignCount, time.Now().UnixMilli(), target, username)
	return err
}

// List returns a user's passkeys for the settings UI. Secrets are never
// included.
func (s *PasskeyStore) List(ctx context.Context, username string) ([]PasskeyInfo, error) {
	username = NormaliseUsername(username)
	rows, err := s.db.QueryContext(ctx,
		`SELECT credential_id, label, created_at, last_used, backed_up
		 FROM passkeys WHERE username=? ORDER BY created_at`, username)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PasskeyInfo
	for rows.Next() {
		var sealedID []byte
		var label sql.NullString
		var created int64
		var lastUsed sql.NullInt64
		var backedUp int
		if err := rows.Scan(&sealedID, &label, &created, &lastUsed, &backedUp); err != nil {
			return nil, err
		}
		info := PasskeyInfo{
			IDPrefix:  fmt.Sprintf("%x", sealedID[:min(6, len(sealedID))]),
			Label:     label.String,
			CreatedAt: created,
			BackedUp:  backedUp == 1,
		}
		if lastUsed.Valid {
			v := lastUsed.Int64
			info.LastUsed = &v
		}
		out = append(out, info)
	}
	return out, rows.Err()
}

// PasskeyInfo is a passkey row for display.
type PasskeyInfo struct {
	IDPrefix  string
	Label     string
	CreatedAt int64
	LastUsed  *int64
	BackedUp  bool
}

// Delete removes a passkey by its sealed id prefix.
func (s *PasskeyStore) Delete(ctx context.Context, username, idPrefix string) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT credential_id FROM passkeys WHERE username=?`, NormaliseUsername(username))
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sealedID []byte
		if err := rows.Scan(&sealedID); err != nil {
			return err
		}
		if fmt.Sprintf("%x", sealedID[:min(6, len(sealedID))]) == idPrefix {
			rows.Close()
			_, err := s.db.ExecContext(ctx,
				`DELETE FROM passkeys WHERE credential_id=? AND username=?`,
				sealedID, NormaliseUsername(username))
			return err
		}
	}
	return ErrNoPasskey
}

// Count returns how many passkeys a user has registered.
func (s *PasskeyStore) Count(ctx context.Context, username string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM passkeys WHERE username=?`, NormaliseUsername(username)).Scan(&n)
	return n, err
}
