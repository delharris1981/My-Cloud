package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/derek/my-cloud/internal/crypt"
)

// The legacy JSON shapes, transcribed from the Node version's auth.js and
// shares.js. Field names are camelCase as they appear on disk.
//
// These types exist only to read the old files. Nothing writes them again.

// legacyUsersFile is the parsed users.json.
type legacyUsersFile struct {
	Users []legacyUser `json:"users"`
}

type legacyUser struct {
	Username          string            `json:"username"`
	PasswordHash      string            `json:"passwordHash"`
	IsAdmin           bool              `json:"isAdmin"`
	QuotaMB           *float64          `json:"quotaMB"`
	CreatedAt         int64             `json:"createdAt"`
	PasswordChangedAt int64             `json:"passwordChangedAt"`
	TotpSecret        string            `json:"totpSecret"`
	TotpPending       string            `json:"totpPending"`
	Recovery          []string          `json:"recovery"`
	AppPasswords      []legacyAppPasswd `json:"appPasswords"`
}

type legacyAppPasswd struct {
	ID        string `json:"id"`
	Label     string `json:"label"`
	Hash      string `json:"hash"`
	CreatedAt int64  `json:"createdAt"`
}

type legacySharesFile struct {
	Shares []legacyShare `json:"shares"`
}

type legacyShare struct {
	Token        string   `json:"token"`
	Owner        string   `json:"owner"`
	PasswordHash string   `json:"passwordHash"`
	ExpiresAt    *int64   `json:"expiresAt"`
	CreatedAt    int64    `json:"createdAt"`
	Downloads    int      `json:"downloads"`
	Path         string   `json:"path"`
	IsDir        bool     `json:"isDir"`
	AllowUpload  bool     `json:"allowUpload"`
	IsMulti      bool     `json:"isMulti"`
	Items        []string `json:"items"`
}

// migrateLockPath is the flock target that stops two containers racing the
// migration. The strangler rollout deliberately runs both servers against the
// same volumes, so this is load-bearing, not defensive.
func migrateLockPath(configDir string) string {
	return filepath.Join(configDir, ".migrate.lock")
}

// MigrateResult describes what a migration run did.
type MigrateResult struct {
	Ran           bool
	Users         int
	Shares        int
	AppPasswords  int
	TOTPUsers     int
	RecoveryCodes int
	OriginalsKept []string
}

// Migrate imports a Node config directory into SQLite, once.
//
// Detection, per the schema doc: migrate when no schema_meta row exists AND
// users.json is present. Otherwise open. The completion marker is written in
// the same transaction as the data, so a crash mid-migration leaves the
// database un-migrated and the next boot safely retries.
//
// Returns a zero Result (Ran=false) when there is nothing to do.
func Migrate(ctx context.Context, db *DB, configDir string, sealer *crypt.Sealer) (MigrateResult, error) {
	var res MigrateResult

	// Take the cross-process lock first. Every exit path releases it.
	unlock, err := acquireMigrateLock(migrateLockPath(configDir))
	if err != nil {
		return res, err
	}
	defer unlock()

	// Re-check under the lock: another container may have migrated while we
	// waited for it.
	done, err := db.Migrated(ctx)
	if err != nil {
		return res, err
	}
	if done {
		return res, nil
	}

	usersPath := filepath.Join(configDir, "users.json")
	if _, err := os.Stat(usersPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Fresh install, not a migration. Stamp the marker anyway so the
			// check is unambiguous from here on.
			if err := stampMigrated(ctx, db, false); err != nil {
				return res, err
			}
			return res, nil
		}
		return res, fmt.Errorf("sqlite: stat users.json: %w", err)
	}

	// users.json is the critical file. A corrupt one aborts startup rather
	// than resetting to {users:[]} — that would delete every account AND
	// reopen admin setup to the world. Same rule as the Node JsonStore's
	// critical flag.
	users, err := readLegacy[legacyUsersFile](usersPath, true)
	if err != nil {
		return res, err
	}

	// shares.json is non-critical: if it is missing or corrupt, migrate the
	// users and say so, rather than refusing to boot the whole server.
	shares, shareErr := readLegacy[legacySharesFile](filepath.Join(configDir, "shares.json"), false)
	if shareErr != nil {
		shares = legacySharesFile{}
		fmt.Fprintf(os.Stderr, "migrate: shares.json skipped: %v\n", shareErr)
	}

	// One transaction. Either the whole import lands or none of it does.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return res, fmt.Errorf("sqlite: begin migration: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op after a successful commit

	if err := importUsers(ctx, tx, users, sealer, &res); err != nil {
		return res, err
	}
	if err := importShares(ctx, tx, shares, &res); err != nil {
		return res, err
	}

	if _, err := tx.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES('node_migrated_at', ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		fmt.Sprint(time.Now().UnixMilli())); err != nil {
		return res, fmt.Errorf("sqlite: stamp migration: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return res, fmt.Errorf("sqlite: commit migration: %w", err)
	}

	res.Ran = true
	// Rename the originals rather than deleting them, so a rollback to the
	// Node version stays a `mv` away. Done after the commit: before it, a
	// failed import would have destroyed the only copy.
	res.OriginalsKept = renameOriginals(configDir, []string{"users.json", "shares.json"})
	return res, nil
}

func importUsers(ctx context.Context, tx *txRunner, f legacyUsersFile, sealer *crypt.Sealer, res *MigrateResult) error {
	for _, u := range f.Users {
		if u.Username == "" || u.PasswordHash == "" {
			return fmt.Errorf("migrate: user entry missing username or passwordHash")
		}
		// quotaMB: 0 (or absent) means unlimited, which is NULL in the schema.
		var quota any
		if u.QuotaMB != nil && *u.QuotaMB > 0 {
			quota = int(*u.QuotaMB)
		}

		created := u.CreatedAt
		if created == 0 {
			created = time.Now().UnixMilli()
		}
		changed := u.PasswordChangedAt
		if changed == 0 {
			changed = created
		}

		// The bcrypt hash is copied verbatim. verifyPassword accepts both
		// formats and re-hashes with argon2id lazily on first login, so there
		// is no forced reset.
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO users(username, pw_hash, is_admin, quota_mb, created_at, password_changed_at)
			 VALUES(?,?,?,?,?,?)`,
			u.Username, u.PasswordHash, boolToInt(u.IsAdmin), quota, created, changed); err != nil {
			return fmt.Errorf("migrate: insert user %q: %w", u.Username, err)
		}
		res.Users++

		// TOTP secrets are re-sealed: they were plaintext base32 in the JSON.
		if u.TotpSecret != "" || u.TotpPending != "" {
			// secret is NOT NULL: a user who began enrolment but never
			// confirmed has only a pending secret, so default it to an empty
			// blob rather than nil. enabled stays 0, so the empty secret is
			// never verified against.
			secret, pending := []byte{}, any(nil)
			if u.TotpSecret != "" {
				// AAD binds the blob to this table+row, so it cannot be
				// transplanted to another user's row.
				sealed, err := sealer.SealString(crypt.PurposeSecrets,
					aad("totp", u.Username), u.TotpSecret)
				if err != nil {
					return fmt.Errorf("migrate: seal totp for %q: %w", u.Username, err)
				}
				secret = sealed
			}
			if u.TotpPending != "" {
				sealed, err := sealer.SealString(crypt.PurposeSecrets,
					aad("totp.pending", u.Username), u.TotpPending)
				if err != nil {
					return fmt.Errorf("migrate: seal totp pending for %q: %w", u.Username, err)
				}
				pending = sealed
			}
			created := u.CreatedAt
			if created == 0 {
				created = time.Now().UnixMilli()
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO totp(username, secret, pending, enabled, created_at)
				 VALUES(?,?,?,?,?)`,
				u.Username, secret, pending, boolToInt(u.TotpSecret != ""), created); err != nil {
				return fmt.Errorf("migrate: insert totp for %q: %w", u.Username, err)
			}
			res.TOTPUsers++
		}

		// Recovery codes stay bcrypt — they are low-entropy and checked in a
		// loop, so cost is a DoS knob there, not a storage concern.
		for _, h := range u.Recovery {
			if h == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO recovery_codes(username, code_hash) VALUES(?,?)`,
				u.Username, h); err != nil {
				return fmt.Errorf("migrate: insert recovery code for %q: %w", u.Username, err)
			}
			res.RecoveryCodes++
		}

		for _, ap := range u.AppPasswords {
			if ap.ID == "" || ap.Hash == "" {
				continue
			}
			created := ap.CreatedAt
			if created == 0 {
				created = time.Now().UnixMilli()
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO app_passwords(id, username, label, pw_hash, created_at)
				 VALUES(?,?,?,?,?)`,
				ap.ID, u.Username, ap.Label, ap.Hash, created); err != nil {
				return fmt.Errorf("migrate: insert app password for %q: %w", u.Username, err)
			}
			res.AppPasswords++
		}
	}
	return nil
}

func importShares(ctx context.Context, tx *txRunner, f legacySharesFile, res *MigrateResult) error {
	for _, s := range f.Shares {
		if s.Token == "" || s.Owner == "" {
			return fmt.Errorf("migrate: share entry missing token or owner")
		}
		// A share whose owner no longer exists violates the FK and would
		// abort the whole migration. Drop it with a warning: shares are
		// recreatable, and one stale share must not block the import.
		var ownerExists int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM users WHERE username=?`, s.Owner).Scan(&ownerExists); err != nil {
			return fmt.Errorf("migrate: check share owner: %w", err)
		}
		if ownerExists == 0 {
			fmt.Fprintf(os.Stderr, "migrate: dropping share %q owned by unknown user %q\n", s.Token, s.Owner)
			continue
		}

		created := s.CreatedAt
		if created == 0 {
			created = time.Now().UnixMilli()
		}
		var pw any
		if s.PasswordHash != "" {
			pw = s.PasswordHash // bcrypt, verbatim
		}
		var expires any
		if s.ExpiresAt != nil && *s.ExpiresAt > 0 {
			expires = *s.ExpiresAt
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO shares(token, owner, pw_hash, expires_at, allow_upload, downloads, created_at)
			 VALUES(?,?,?,?,?,?,?)`,
			s.Token, s.Owner, pw, expires, boolToInt(s.AllowUpload), s.Downloads, created); err != nil {
			return fmt.Errorf("migrate: insert share %q: %w", s.Token, err)
		}
		res.Shares++

		// Items: a multi-selection share has items[], a single share has path.
		// Both become share_items rows; ordinal preserves selection order.
		items := s.Items
		if len(items) == 0 && s.Path != "" {
			items = []string{s.Path}
		}
		for i, p := range items {
			if p == "" {
				continue
			}
			// isDir is only authoritative for the single-item form; the
			// multi form sets it true on the share but not per item, and the
			// filesystem is the real source of truth at request time.
			isDir := s.IsDir
			if s.IsMulti {
				isDir = false
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO share_items(token, ordinal, path, is_dir) VALUES(?,?,?,?)`,
				s.Token, i, normalisePath(p), boolToInt(isDir)); err != nil {
				return fmt.Errorf("migrate: insert share item %q/%d: %w", s.Token, i, err)
			}
		}
	}
	return nil
}

// normalisePath converts a legacy path to the form vfs.Resolve expects:
// forward slashes, no leading slash. Never absolute.
func normalisePath(p string) string {
	out := make([]rune, 0, len(p))
	for _, r := range p {
		if r == '\\' {
			r = '/'
		}
		out = append(out, r)
	}
	s := string(out)
	for len(s) > 0 && s[0] == '/' {
		s = s[1:]
	}
	return s
}

// readLegacy parses a legacy JSON file. If critical is true a parse failure is
// fatal; otherwise the error is returned for the caller to decide.
func readLegacy[T any](path string, critical bool) (T, error) {
	var out T
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) && !critical {
			return out, nil // absent and optional: nothing to import
		}
		return out, fmt.Errorf("migrate: read %s: %w", path, err)
	}
	if err := json.Unmarshal(b, &out); err != nil {
		if critical {
			return out, fmt.Errorf("refusing to start: %s is corrupt (%v). "+
				"Restore it from a backup or delete it deliberately, then restart", path, err)
		}
		return out, fmt.Errorf("migrate: parse %s: %w", path, err)
	}
	return out, nil
}

func stampMigrated(ctx context.Context, db *DB, fromNode bool) error {
	v := "0"
	if fromNode {
		v = fmt.Sprint(time.Now().UnixMilli())
	}
	_, err := db.ExecContext(ctx,
		`INSERT INTO schema_meta(key, value) VALUES('node_migrated_at', ?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, v)
	return err
}

// renameOriginals moves the legacy files to *.migrated.bak after a successful
// import. It never deletes: rollback to the Node version must stay possible
// during the side-by-side comparison.
func renameOriginals(configDir string, names []string) []string {
	var kept []string
	for _, n := range names {
		src := filepath.Join(configDir, n)
		dst := src + ".migrated.bak"
		if _, err := os.Stat(src); err != nil {
			continue
		}
		// Don't clobber an existing backup from an earlier migration attempt.
		if _, err := os.Stat(dst); err == nil {
			dst = fmt.Sprintf("%s.migrated.bak.%d", src, time.Now().Unix())
		}
		if err := os.Rename(src, dst); err != nil {
			fmt.Fprintf(os.Stderr, "migrate: warning: could not rename %s: %v\n", src, err)
			continue
		}
		kept = append(kept, dst)
	}
	return kept
}

func aad(table, pk string) string { return table + ":" + pk }

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
