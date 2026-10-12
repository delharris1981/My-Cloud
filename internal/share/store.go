// Package share manages public share links: creation, listing, revocation,
// and the item rows a multi-selection share is built from.
//
// Passwords are bcrypt hashes copied verbatim from the Node migration; they are
// not re-sealed, matching the schema's decision for shares.
package share

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrNotFound is returned for an unknown or revoked token.
//
// Public handlers must not distinguish this from a wrong password or an expired
// link in their *response*: a different status code or message would turn the
// share endpoint into a token oracle. The distinction is available
// internally for logging only.
var ErrNotFound = errors.New("share not found")

// Share is a share link row plus its items.
//
// JSON field names are camelCase to match the shape the existing frontend
// already parses, so an in-place upgrade does not need a client change.
type Share struct {
	Token       string `json:"token"`
	Owner       string `json:"owner"`
	ExpiresAt   *int64 `json:"expiresAt"`
	AllowUpload bool   `json:"allowUpload"`
	Downloads   int    `json:"downloads"`
	CreatedAt   int64  `json:"createdAt"`
	HasPassword bool   `json:"hasPassword"`

	Items []Item `json:"items,omitempty"`
	// FirstName is a display label: the single item's name, or "N items".
	FirstName string `json:"name"`
	Expired   bool   `json:"expired"`

	// unlockSecret is the stored bcrypt verifier, kept only so the public
	// unlock cookie can be derived as an HMAC keyed by it.
	unlockSecret string
}

// Item is one shared path, relative to the owner's files root.
type Item struct {
	Ordinal int    `json:"i"`
	Path    string `json:"path"`
	IsDir   bool   `json:"isDir"`
}

// UnlockSecret returns the value used to key a share's unlock cookie. It is
// only meaningful on a Share loaded by Get or List.
//
// The underlying field is unexported on purpose: encoding/json skips
// unexported fields, so a Share can be returned to a client without leaking
// the bcrypt verifier.
func (sh *Share) UnlockSecret() string { return sh.unlockSecret }

// Store manages share links.
type Store struct {
	db *sql.DB
}

// New wires the store.
func New(db *sql.DB) *Store { return &Store{db: db} }

// NewToken returns a 16-byte random token, base64url encoded — the same shape
// the Node version generated, so existing links keep resolving after cutover.
func NewToken() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("share: token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Create inserts a share and its item rows in one transaction.
//
// pwHash is the bcrypt verifier, or "" for an unprotected link. It is passed
// separately rather than stored on Share so a hash cannot be logged or
// serialised by accident.
func (s *Store) Create(ctx context.Context, sh *Share, pwHash string) error {
	if sh.Token == "" {
		tok, err := NewToken()
		if err != nil {
			return err
		}
		sh.Token = tok
	}
	if sh.CreatedAt == 0 {
		sh.CreatedAt = time.Now().UnixMilli()
	}
	var pw any
	if pwHash != "" {
		pw = pwHash
	}
	var expires any
	if sh.ExpiresAt != nil && *sh.ExpiresAt > 0 {
		expires = *sh.ExpiresAt
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO shares(token, owner, pw_hash, expires_at, allow_upload, downloads, created_at)
		 VALUES(?,?,?,?,?,?,?)`,
		sh.Token, sh.Owner, pw, expires, boolInt(sh.AllowUpload), sh.Downloads, sh.CreatedAt); err != nil {
		return fmt.Errorf("share: insert: %w", err)
	}
	for i, item := range sh.Items {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO share_items(token, ordinal, path, is_dir) VALUES(?,?,?,?)`,
			sh.Token, i, NormaliseRel(item.Path), boolInt(item.IsDir)); err != nil {
			return fmt.Errorf("share: insert item: %w", err)
		}
	}
	return tx.Commit()
}

// scanner is satisfied by both *sql.Row and *sql.Rows.
type scanner interface{ Scan(dest ...any) error }

// shareColumns is the select list shared by every read, so the scan order in
// scanShare and the query order cannot drift apart.
const shareColumns = `token, owner, pw_hash, expires_at, allow_upload, downloads, created_at`

func scanShare(sc scanner) (*Share, error) {
	var sh Share
	var pw sql.NullString
	var expires sql.NullInt64
	if err := sc.Scan(&sh.Token, &sh.Owner, &pw, &expires, &sh.AllowUpload, &sh.Downloads, &sh.CreatedAt); err != nil {
		return nil, err
	}
	sh.HasPassword = pw.Valid && pw.String != ""
	sh.unlockSecret = pw.String
	if expires.Valid {
		v := expires.Int64
		sh.ExpiresAt = &v
	}
	return &sh, nil
}

// List returns a user's shares, newest first.
func (s *Store) List(ctx context.Context, owner string) ([]Share, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT `+shareColumns+` FROM shares WHERE owner=? ORDER BY created_at DESC`, owner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Share
	for rows.Next() {
		sh, err := scanShare(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *sh)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		if err := s.loadItems(ctx, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// Get loads one share by token, including its items.
func (s *Store) Get(ctx context.Context, token string) (*Share, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+shareColumns+` FROM shares WHERE token=?`, token)
	sh, err := scanShare(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if err := s.loadItems(ctx, sh); err != nil {
		return nil, err
	}
	return sh, nil
}

func (s *Store) loadItems(ctx context.Context, sh *Share) error {
	rows, err := s.db.QueryContext(ctx,
		`SELECT ordinal, path, is_dir FROM share_items WHERE token=? ORDER BY ordinal`, sh.Token)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.Ordinal, &it.Path, &it.IsDir); err != nil {
			return err
		}
		sh.Items = append(sh.Items, it)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(sh.Items) == 1 {
		sh.FirstName = BaseName(sh.Items[0].Path)
	} else if len(sh.Items) > 1 {
		sh.FirstName = fmt.Sprintf("%d items", len(sh.Items))
	}
	sh.Expired = sh.IsExpired(time.Now())
	return nil
}

// IsExpired reports whether the share has lapsed.
func (sh *Share) IsExpired(now time.Time) bool {
	return sh.ExpiresAt != nil && *sh.ExpiresAt > 0 && now.UnixMilli() > *sh.ExpiresAt
}

// Delete revokes a share, scoped by owner so one user cannot revoke another's
// link even holding a valid token.
func (s *Store) Delete(ctx context.Context, owner, token string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM shares WHERE token=? AND owner=?`, token, owner)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountDownload increments the counter. The frequently-bumped column now lives
// in SQLite, so this is a cheap row update rather than a JSON rewrite.
func (s *Store) CountDownload(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE shares SET downloads = downloads + 1 WHERE token=?`, token)
	return err
}

// DeleteForOwner removes every share belonging to a user, called when an
// account is deleted.
func (s *Store) DeleteForOwner(ctx context.Context, owner string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM shares WHERE owner=?`, owner)
	return err
}

// NormaliseRel reduces a path to a forward-slash relative form with no leading
// slash. Values reaching here come from disk or a request, so they are treated
// as untrusted; vfs.Resolve is the real guard, this is just tidy-up.
func NormaliseRel(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	return strings.TrimLeft(p, "/")
}

// BaseName returns the last path segment.
func BaseName(p string) string {
	p = strings.TrimRight(NormaliseRel(p), "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
