package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// AppPassword is a WebDAV/Basic-auth credential. Hashes never leave the store.
type AppPassword struct {
	ID        string
	Label     string
	CreatedAt int64
	LastUsed  *int64
}

// AppPasswordStore manages app passwords.
type AppPasswordStore struct {
	db *sql.DB
}

// NewAppPasswordStore wires the store.
func NewAppPasswordStore(db *sql.DB) *AppPasswordStore {
	return &AppPasswordStore{db: db}
}

// Create mints a new app password and returns the plaintext token, shown once.
// The caller must display it; only the argon2id hash is stored.
func (a *AppPasswordStore) Create(ctx context.Context, username, label string) (id, token string, err error) {
	username = NormaliseUsername(username)
	if label == "" {
		label = "App"
	}
	if len(label) > 40 {
		label = label[:40]
	}
	id, err = randomHex(4) // 8 hex chars, matching the Node id format
	if err != nil {
		return "", "", err
	}
	raw, err := randomHex(30) // 60 hex chars, comparable entropy to the Node 15-byte token
	if err != nil {
		return "", "", err
	}
	hash, err := HashAppPassword(raw)
	if err != nil {
		return "", "", err
	}
	if _, err := a.db.ExecContext(ctx,
		`INSERT INTO app_passwords(id, username, label, pw_hash, created_at) VALUES(?,?,?,?,?)`,
		id, username, label, hash, time.Now().UnixMilli()); err != nil {
		return "", "", fmt.Errorf("auth: insert app password: %w", err)
	}
	return id, raw, nil
}

// List returns a user's app passwords without hashes.
func (a *AppPasswordStore) List(ctx context.Context, username string) ([]AppPassword, error) {
	rows, err := a.db.QueryContext(ctx,
		`SELECT id, label, created_at, last_used FROM app_passwords WHERE username=? ORDER BY created_at`,
		NormaliseUsername(username))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppPassword
	for rows.Next() {
		var p AppPassword
		var lastUsed sql.NullInt64
		if err := rows.Scan(&p.ID, &p.Label, &p.CreatedAt, &lastUsed); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			v := lastUsed.Int64
			p.LastUsed = &v
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Remove deletes one app password.
func (a *AppPasswordStore) Remove(ctx context.Context, username, id string) error {
	_, err := a.db.ExecContext(ctx,
		`DELETE FROM app_passwords WHERE username=? AND id=?`, NormaliseUsername(username), id)
	return err
}

// VerifyAppPassword checks a Basic-auth credential for a user, returning the
// user on success. A missing user burns a dummy comparison so timing does not
// enumerate accounts.
//
// It returns (user, ok). Callers use ok to distinguish "wrong credential" from
// "no such user", but must present the same error to the client either way.
func (a *AppPasswordStore) VerifyAppPassword(ctx context.Context, username, candidate string) (*User, bool) {
	username = NormaliseUsername(username)
	u, pwHash, err := FindUserWithHashStore(ctx, a.db, username)
	if err != nil {
		DummyCompare()
		return nil, false
	}
	// The candidate list is read fully and the cursor closed *before* any
	// write. With MaxOpenConns(1) an open rows cursor holds the only
	// connection, so a write issued mid-iteration would wait for a connection
	// that cannot be released until the iteration finishes — a self-deadlock.
	rows, err := a.db.QueryContext(ctx,
		`SELECT id, pw_hash FROM app_passwords WHERE username=?`, username)
	if err != nil {
		return nil, false
	}
	type apppw struct{ id, hash string }
	var candidates []apppw
	for rows.Next() {
		var c apppw
		if err := rows.Scan(&c.id, &c.hash); err == nil {
			candidates = append(candidates, c)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, false
	}

	for _, c := range candidates {
		upgrade, ok := CompareAppPassword(c.hash, candidate)
		if !ok {
			continue
		}
		if upgrade {
			if newHash, err := HashAppPassword(candidate); err == nil {
				_, _ = a.db.ExecContext(ctx, `UPDATE app_passwords SET pw_hash=? WHERE id=?`, newHash, c.id)
			}
		}
		_, _ = a.db.ExecContext(ctx, `UPDATE app_passwords SET last_used=? WHERE id=?`,
			time.Now().UnixMilli(), c.id)
		u.HasTOTP = TOTPEnabledFor(ctx, a.db, username)
		return u, true
	}
	// No app password matched. Fall back to the account password, but only
	// when 2FA is off — otherwise accepting it here would be a 2FA bypass.
	if u.HasTOTP {
		DummyCompare()
		return nil, false
	}
	_, ok := CompareAppPassword(pwHash, candidate)
	return u, ok
}

// FindUserWithHashStore is a package-level helper shared with Store, kept here
// so the app-password path does not need a Store instance.
func FindUserWithHashStore(ctx context.Context, db *sql.DB, username string) (*User, string, error) {
	var u User
	var quota sql.NullInt64
	var hash string
	var hasTOTP int
	err := db.QueryRowContext(ctx,
		`SELECT u.username, u.pw_hash, u.is_admin, u.quota_mb, u.created_at, u.password_changed_at,
		        EXISTS(SELECT 1 FROM totp t WHERE t.username=u.username AND t.enabled=1)
		 FROM users u WHERE u.username=?`, username).
		Scan(&u.Username, &hash, &u.IsAdmin, &quota, &u.CreatedAt, &u.PasswordChangedAt, &hasTOTP)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, "", sql.ErrNoRows
		}
		return nil, "", err
	}
	u.QuotaMB = int(quota.Int64)
	u.HasTOTP = hasTOTP == 1
	return &u, hash, nil
}

// TOTPEnabledFor reports whether 2FA is active for a user.
func TOTPEnabledFor(ctx context.Context, db *sql.DB, username string) bool {
	var enabled int
	err := db.QueryRowContext(ctx, `SELECT enabled FROM totp WHERE username=?`, username).Scan(&enabled)
	return err == nil && enabled == 1
}
