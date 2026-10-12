package sqlite

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/derek/my-cloud/internal/crypt"
)

// legacyJSON writes a file into dir and returns its path.
func legacyJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal %s: %v", name, err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// bcryptHash is a syntactically valid bcrypt string. The migration copies
// hashes verbatim without verifying them, so the value only has to be copied
// faithfully — it need not correspond to a real password.
const bcryptHash = "$2a$10$abcdefghijklmnopqrstuvABCDEFGHIJKLMNOPQRSTUVWXYZ012345"

func testSealer(t *testing.T) *crypt.Sealer {
	t.Helper()
	s, err := crypt.New(strings.Repeat("ab", 48))
	if err != nil {
		t.Fatalf("crypt.New: %v", err)
	}
	return s
}

// freshDB opens a database in a temp dir, wired up like main does.
func freshDB(t *testing.T, configDir string) *DB {
	t.Helper()
	db, err := Open(filepath.Join(configDir, "my-cloud.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestMigrateUsersVerbatim(t *testing.T) {
	dir := t.TempDir()
	legacyJSON(t, dir, "users.json", map[string]any{
		"users": []any{
			map[string]any{
				"username": "alice", "passwordHash": bcryptHash, "isAdmin": true,
				"quotaMB": 2048, "createdAt": 1700000000000, "passwordChangedAt": 1700000001000,
			},
			map[string]any{
				"username": "bob", "passwordHash": bcryptHash, "isAdmin": false,
				"quotaMB": 0, "createdAt": 1700000002000, "passwordChangedAt": 1700000002000,
			},
		},
	})

	db := freshDB(t, dir)
	res, err := Migrate(context.Background(), db, dir, testSealer(t))
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if !res.Ran || res.Users != 2 {
		t.Fatalf("expected 2 users migrated, got ran=%v users=%d", res.Ran, res.Users)
	}

	var hash string
	var isAdmin int
	var quota any
	err = db.QueryRow(`SELECT pw_hash, is_admin, quota_mb FROM users WHERE username='alice'`).
		Scan(&hash, &isAdmin, &quota)
	if err != nil {
		t.Fatalf("query alice: %v", err)
	}
	// The bcrypt hash must survive byte-for-byte: there is no forced reset.
	if hash != bcryptHash {
		t.Fatalf("bcrypt hash was rewritten: %q", hash)
	}
	if isAdmin != 1 {
		t.Fatalf("alice should be admin, got %d", isAdmin)
	}
	if quota != int64(2048) {
		t.Fatalf("quota should be 2048, got %v", quota)
	}

	// quotaMB 0 means unlimited, which the schema represents as NULL.
	var bobQuota any
	if err := db.QueryRow(`SELECT quota_mb FROM users WHERE username='bob'`).Scan(&bobQuota); err != nil {
		t.Fatalf("query bob: %v", err)
	}
	if bobQuota != nil {
		t.Fatalf("quota 0 should migrate to NULL, got %v", bobQuota)
	}
}

func TestMigrateReSealsTOTPSecrets(t *testing.T) {
	dir := t.TempDir()
	legacyJSON(t, dir, "users.json", map[string]any{
		"users": []any{map[string]any{
			"username": "alice", "passwordHash": bcryptHash,
			"createdAt": 1, "passwordChangedAt": 1,
			"totpSecret": "JBSWY3DPEHPK3PXP", "totpPending": "KRUGS4ZANFZSAYJA",
			"recovery": []string{bcryptHash, bcryptHash},
		}},
	})

	db := freshDB(t, dir)
	sealer := testSealer(t)
	if _, err := Migrate(context.Background(), db, dir, sealer); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	var secret, pending []byte
	var enabled int
	if err := db.QueryRow(`SELECT secret, pending, enabled FROM totp WHERE username='alice'`).
		Scan(&secret, &pending, &enabled); err != nil {
		t.Fatalf("query totp: %v", err)
	}
	if enabled != 1 {
		t.Fatalf("totp should be enabled, got %d", enabled)
	}
	// The stored blob must not be the plaintext base32 secret.
	if strings.Contains(string(secret), "JBSWY3DPEHPK3PXP") {
		t.Fatal("TOTP secret was stored in plaintext; it must be sealed at rest")
	}
	got, err := sealer.OpenString(crypt.PurposeSecrets, "totp:alice", secret)
	if err != nil {
		t.Fatalf("sealed secret does not decrypt under the expected AAD: %v", err)
	}
	if got != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("TOTP secret round-trip mismatch: %q", got)
	}
	if gotPending, err := sealer.OpenString(crypt.PurposeSecrets, "totp.pending:alice", pending); err != nil {
		t.Fatalf("pending secret does not decrypt: %v", err)
	} else if gotPending != "KRUGS4ZANFZSAYJA" {
		t.Fatalf("pending round-trip mismatch: %q", gotPending)
	}

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM recovery_codes WHERE username='alice'`).Scan(&n); err != nil {
		t.Fatalf("count recovery: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 recovery codes, got %d", n)
	}
}

func TestMigrateAppPasswords(t *testing.T) {
	dir := t.TempDir()
	legacyJSON(t, dir, "users.json", map[string]any{
		"users": []any{map[string]any{
			"username": "alice", "passwordHash": bcryptHash, "createdAt": 1, "passwordChangedAt": 1,
			"appPasswords": []any{
				map[string]any{"id": "abc123", "label": "Finder", "hash": bcryptHash, "createdAt": 1700000000},
			},
		}},
	})
	db := freshDB(t, dir)
	res, err := Migrate(context.Background(), db, dir, testSealer(t))
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.AppPasswords != 1 {
		t.Fatalf("expected 1 app password, got %d", res.AppPasswords)
	}
	var hash string
	if err := db.QueryRow(`SELECT pw_hash FROM app_passwords WHERE id='abc123'`).Scan(&hash); err != nil {
		t.Fatalf("query app password: %v", err)
	}
	if hash != bcryptHash {
		t.Fatalf("app password hash was rewritten: %q", hash)
	}
}

func TestMigrateSharesBothShapes(t *testing.T) {
	dir := t.TempDir()
	legacyJSON(t, dir, "users.json", map[string]any{
		"users": []any{map[string]any{
			"username": "alice", "passwordHash": bcryptHash, "createdAt": 1, "passwordChangedAt": 1,
		}},
	})
	legacyJSON(t, dir, "shares.json", map[string]any{
		"shares": []any{
			// Single-item file share with a password and expiry.
			map[string]any{
				"token": "tok-single", "owner": "alice", "passwordHash": bcryptHash,
				"expiresAt": 1800000000000, "createdAt": 1700000000000,
				"downloads": 7, "path": "docs/report.pdf", "isDir": false, "allowUpload": false,
			},
			// Multi-item share: no path, an items array.
			map[string]any{
				"token": "tok-multi", "owner": "alice", "passwordHash": nil,
				"expiresAt": nil, "createdAt": 1700000001000, "downloads": 0,
				"isMulti": true, "items": []string{"a.txt", "b/c.txt"}, "isDir": true, "allowUpload": false,
			},
		},
	})

	db := freshDB(t, dir)
	res, err := Migrate(context.Background(), db, dir, testSealer(t))
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.Shares != 2 {
		t.Fatalf("expected 2 shares, got %d", res.Shares)
	}

	var pw any
	var expires any
	var downloads int
	if err := db.QueryRow(`SELECT pw_hash, expires_at, downloads FROM shares WHERE token='tok-single'`).
		Scan(&pw, &expires, &downloads); err != nil {
		t.Fatalf("query single share: %v", err)
	}
	if pw != bcryptHash {
		t.Fatalf("share password hash was rewritten: %v", pw)
	}
	if expires != int64(1800000000000) {
		t.Fatalf("expiry mismatch: %v", expires)
	}
	if downloads != 7 {
		t.Fatalf("download counter lost: got %d, want 7", downloads)
	}

	// Single share becomes exactly one item row.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM share_items WHERE token='tok-single'`).Scan(&n); err != nil {
		t.Fatalf("count single items: %v", err)
	}
	if n != 1 {
		t.Fatalf("single share should have 1 item, got %d", n)
	}

	// Multi share preserves order via ordinal.
	rows, err := db.Query(`SELECT ordinal, path FROM share_items WHERE token='tok-multi' ORDER BY ordinal`)
	if err != nil {
		t.Fatalf("query multi items: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var o int
		var p string
		if err := rows.Scan(&o, &p); err != nil {
			t.Fatalf("scan item: %v", err)
		}
		got = append(got, p)
	}
	if len(got) != 2 || got[0] != "a.txt" || got[1] != "b/c.txt" {
		t.Fatalf("multi-item order not preserved: %v", got)
	}
}

func TestMigrateShareNormalisesPaths(t *testing.T) {
	dir := t.TempDir()
	legacyJSON(t, dir, "users.json", map[string]any{
		"users": []any{map[string]any{
			"username": "alice", "passwordHash": bcryptHash, "createdAt": 1, "passwordChangedAt": 1,
		}},
	})
	legacyJSON(t, dir, "shares.json", map[string]any{
		"shares": []any{map[string]any{
			"token": "t", "owner": "alice", "createdAt": 1, "downloads": 0,
			"path": "/leading/slash.txt", "isDir": false,
		}},
	})
	db := freshDB(t, dir)
	if _, err := Migrate(context.Background(), db, dir, testSealer(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	var p string
	if err := db.QueryRow(`SELECT path FROM share_items WHERE token='t'`).Scan(&p); err != nil {
		t.Fatalf("query item: %v", err)
	}
	// No leading slash: share_items.path is always relative to the files root.
	if p != "leading/slash.txt" {
		t.Fatalf("path not normalised: %q", p)
	}
}

func TestMigrateSkipsShareWithUnknownOwner(t *testing.T) {
	dir := t.TempDir()
	legacyJSON(t, dir, "users.json", map[string]any{
		"users": []any{map[string]any{
			"username": "alice", "passwordHash": bcryptHash, "createdAt": 1, "passwordChangedAt": 1,
		}},
	})
	legacyJSON(t, dir, "shares.json", map[string]any{
		"shares": []any{
			map[string]any{"token": "orphan", "owner": "ghost", "createdAt": 1, "path": "x.txt"},
			map[string]any{"token": "good", "owner": "alice", "createdAt": 1, "path": "y.txt"},
		},
	})
	db := freshDB(t, dir)
	res, err := Migrate(context.Background(), db, dir, testSealer(t))
	if err != nil {
		t.Fatalf("Migrate should skip the orphan, not abort: %v", err)
	}
	if res.Shares != 1 {
		t.Fatalf("expected 1 share, got %d", res.Shares)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	legacyJSON(t, dir, "users.json", map[string]any{
		"users": []any{map[string]any{
			"username": "alice", "passwordHash": bcryptHash, "createdAt": 1, "passwordChangedAt": 1,
		}},
	})
	db := freshDB(t, dir)

	if res, err := Migrate(context.Background(), db, dir, testSealer(t)); err != nil || !res.Ran {
		t.Fatalf("first migrate: ran=%v err=%v", res.Ran, err)
	}
	// Second run must be a no-op, not a duplicate-key error.
	res2, err := Migrate(context.Background(), db, dir, testSealer(t))
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if res2.Ran {
		t.Fatal("second migration ran again; it is not idempotent")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 user after two runs, got %d", n)
	}
}

func TestMigrateRenamesOriginalsNotDeletes(t *testing.T) {
	dir := t.TempDir()
	usersPath := legacyJSON(t, dir, "users.json", map[string]any{
		"users": []any{map[string]any{
			"username": "alice", "passwordHash": bcryptHash, "createdAt": 1, "passwordChangedAt": 1,
		}},
	})
	sharesPath := legacyJSON(t, dir, "shares.json", map[string]any{"shares": []any{}})

	db := freshDB(t, dir)
	if _, err := Migrate(context.Background(), db, dir, testSealer(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	// Rollback to Node must stay possible, so originals are renamed, not deleted.
	if _, err := os.Stat(usersPath); !os.IsNotExist(err) {
		t.Fatal("users.json was not renamed")
	}
	if _, err := os.Stat(usersPath + ".migrated.bak"); err != nil {
		t.Fatalf("users.json.migrated.bak missing: %v", err)
	}
	if _, err := os.Stat(sharesPath + ".migrated.bak"); err != nil {
		t.Fatalf("shares.json.migrated.bak missing: %v", err)
	}
}

func TestMigrateFreshInstallDoesNothing(t *testing.T) {
	dir := t.TempDir()
	db := freshDB(t, dir)
	res, err := Migrate(context.Background(), db, dir, testSealer(t))
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.Ran || res.Users != 0 {
		t.Fatalf("fresh install should not migrate: ran=%v users=%d", res.Ran, res.Users)
	}
	// It must still stamp the marker so the next boot is unambiguous.
	done, err := db.Migrated(context.Background())
	if err != nil {
		t.Fatalf("Migrated: %v", err)
	}
	if !done {
		t.Fatal("fresh install did not stamp the migration marker")
	}
}

func TestMigrateRefusesCorruptUsers(t *testing.T) {
	dir := t.TempDir()
	// Truncated JSON, as a crash mid-write would leave.
	if err := os.WriteFile(filepath.Join(dir, "users.json"), []byte(`{"users":[{"user`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	db := freshDB(t, dir)
	_, err := Migrate(context.Background(), db, dir, testSealer(t))
	if err == nil {
		t.Fatal("migrated a corrupt users.json; refusing to boot is required")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("error should name the corruption, got: %v", err)
	}
	// Crucially, no users must have been created — a silent reset here would
	// delete every account and reopen admin setup to the world.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 0 {
		t.Fatalf("users written despite corrupt input: %d", n)
	}
}

func TestMigrateToleratesCorruptShares(t *testing.T) {
	dir := t.TempDir()
	legacyJSON(t, dir, "users.json", map[string]any{
		"users": []any{map[string]any{
			"username": "alice", "passwordHash": bcryptHash, "createdAt": 1, "passwordChangedAt": 1,
		}},
	})
	if err := os.WriteFile(filepath.Join(dir, "shares.json"), []byte("not json at all"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	db := freshDB(t, dir)
	res, err := Migrate(context.Background(), db, dir, testSealer(t))
	if err != nil {
		t.Fatalf("corrupt shares.json should not block startup: %v", err)
	}
	if res.Users != 1 {
		t.Fatalf("users should still have migrated, got %d", res.Users)
	}
}

func TestMigrateEmptyUserListStillMarksMigrated(t *testing.T) {
	dir := t.TempDir()
	legacyJSON(t, dir, "users.json", map[string]any{"users": []any{}})
	db := freshDB(t, dir)
	res, err := Migrate(context.Background(), db, dir, testSealer(t))
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if res.Users != 0 {
		t.Fatalf("expected 0 users, got %d", res.Users)
	}
	done, err := db.Migrated(context.Background())
	if err != nil || !done {
		t.Fatalf("marker should be stamped even with no users: done=%v err=%v", done, err)
	}
}

func TestMigrateMissingTimestampsGetDefaults(t *testing.T) {
	dir := t.TempDir()
	legacyJSON(t, dir, "users.json", map[string]any{
		"users": []any{map[string]any{
			"username": "alice", "passwordHash": bcryptHash,
			// createdAt / passwordChangedAt deliberately absent.
		}},
	})
	db := freshDB(t, dir)
	if _, err := Migrate(context.Background(), db, dir, testSealer(t)); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	var created, changed int64
	if err := db.QueryRow(`SELECT created_at, password_changed_at FROM users WHERE username='alice'`).
		Scan(&created, &changed); err != nil {
		t.Fatalf("query: %v", err)
	}
	// The column is NOT NULL; a legacy file missing the field must not abort
	// the whole migration.
	if created == 0 || changed == 0 {
		t.Fatalf("timestamps defaulted to zero: created=%d changed=%d", created, changed)
	}
}
