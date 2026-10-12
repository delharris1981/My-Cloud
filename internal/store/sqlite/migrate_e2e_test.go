package sqlite

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/derek/my-cloud/internal/crypt"
)

// TestMigrateRealNodeConfig is the end-to-end check that matters most: it
// migrates a /config produced by the actual Node application (real bcrypt
// hashes, a real TOTP secret, real share records) rather than fixtures
// invented by this repo, then proves the result is still usable.
//
// Skips if node is unavailable or dev-config-gen.js is missing.
func TestMigrateRealNodeConfig(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node not available; skipping end-to-end legacy migration test")
	}
	gen := filepath.Join("..", "..", "..", "dev-config-gen.js")
	if _, err := os.Stat(gen); err != nil {
		t.Skipf("generator not found: %v", err)
	}

	base := t.TempDir()
	configDir := filepath.Join(base, "config")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Generate a real legacy config with the Node app's own totp.js.
	out, err := exec.Command("node", gen, configDir).Output()
	if err != nil {
		t.Skipf("could not generate legacy config: %v", err)
	}
	var expected struct {
		Secret        string            `json:"secret"`
		TotpSecret    string            `json:"totpSecret"`
		RecoveryShown []string          `json:"recoveryShown"`
		AppPwToken    string            `json:"appPwToken"`
		Passwords     map[string]string `json:"passwords"`
		SharePassword string            `json:"sharePassword"`
	}
	if err := json.Unmarshal(out, &expected); err != nil {
		t.Fatalf("parse generator output: %v", err)
	}

	db := freshDB(t, configDir)
	res, err := Migrate(context.Background(), db, configDir, testSealerFromHex(t, expected.Secret))
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if !res.Ran {
		t.Fatal("migration did not run on a populated /config")
	}
	if res.Users != 3 {
		t.Fatalf("expected 3 users, got %d", res.Users)
	}
	if res.Shares != 3 {
		t.Fatalf("expected 3 shares, got %d", res.Shares)
	}
	if res.TOTPUsers != 1 {
		t.Fatalf("expected 1 TOTP enrolment, got %d", res.TOTPUsers)
	}
	if res.AppPasswords != 1 {
		t.Fatalf("expected 1 app password, got %d", res.AppPasswords)
	}
	if res.RecoveryCodes != 10 {
		t.Fatalf("expected 10 recovery codes, got %d", res.RecoveryCodes)
	}

	// The TOTP secret must decrypt back to exactly what the Node app stored —
	// this is what proves the re-seal round-tripped, and that a user's
	// authenticator app keeps working after cutover.
	sealer := testSealerFromHex(t, expected.Secret)
	var secret []byte
	if err := db.QueryRow(`SELECT secret FROM totp WHERE username='admin'`).Scan(&secret); err != nil {
		t.Fatalf("query totp: %v", err)
	}
	got, err := sealer.OpenString(crypt.PurposeSecrets, "totp:admin", secret)
	if err != nil {
		t.Fatalf("sealed TOTP secret will not decrypt: %v", err)
	}
	if got != expected.TotpSecret {
		t.Fatalf("TOTP secret round-trip mismatch:\n got %q\nwant %q", got, expected.TotpSecret)
	}

	// bcrypt hashes must be byte-identical, since Go cannot recompute them.
	var adminHash string
	if err := db.QueryRow(`SELECT pw_hash FROM users WHERE username='admin'`).Scan(&adminHash); err != nil {
		t.Fatalf("query admin: %v", err)
	}
	rawUsers, err := os.ReadFile(filepath.Join(configDir, "users.json.migrated.bak"))
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	var legacy struct {
		Users []struct {
			Username     string `json:"username"`
			PasswordHash string `json:"passwordHash"`
		} `json:"users"`
	}
	if err := json.Unmarshal(rawUsers, &legacy); err != nil {
		t.Fatalf("parse backup: %v", err)
	}
	found := false
	for _, u := range legacy.Users {
		if u.Username == "admin" {
			found = true
			if u.PasswordHash != adminHash {
				t.Fatalf("admin bcrypt hash was modified during migration")
			}
		}
	}
	if !found {
		t.Fatal("admin missing from the backup file")
	}

	// Unlimited quota must land as NULL for both admin and guest.
	for _, u := range []string{"admin", "guest"} {
		var q any
		if err := db.QueryRow(`SELECT quota_mb FROM users WHERE username=?`, u).Scan(&q); err != nil {
			t.Fatalf("query %s: %v", u, err)
		}
		if q != nil {
			t.Fatalf("%s has quotaMB 0 (unlimited) but stored %v, want NULL", u, q)
		}
	}
	var familyQuota any
	if err := db.QueryRow(`SELECT quota_mb FROM users WHERE username='family'`).Scan(&familyQuota); err != nil {
		t.Fatalf("query family: %v", err)
	}
	if familyQuota != int64(512) {
		t.Fatalf("family quota: got %v, want 512", familyQuota)
	}

	// Multi-item share must preserve selection order.
	rows, err := db.Query(`SELECT ordinal, path FROM share_items WHERE token='multi-item-share-token' ORDER BY ordinal`)
	if err != nil {
		t.Fatalf("query items: %v", err)
	}
	defer rows.Close()
	var order []string
	for rows.Next() {
		var o int
		var p string
		if err := rows.Scan(&o, &p); err != nil {
			t.Fatal(err)
		}
		order = append(order, p)
	}
	want := []string{"report.pdf", "notes", "notes/todo.md"}
	if len(order) != len(want) {
		t.Fatalf("multi-item count: got %v, want %v", order, want)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("multi-item order: got %v, want %v", order, want)
		}
	}

	// The drop-box share must keep its upload permission.
	var allowUpload int
	if err := db.QueryRow(`SELECT allow_upload FROM shares WHERE token='dropbox-share-token'`).Scan(&allowUpload); err != nil {
		t.Fatalf("query dropbox: %v", err)
	}
	if allowUpload != 1 {
		t.Fatal("drop-box share lost its allowUpload flag")
	}

	// A null share password must stay NULL, not become an empty string that
	// would then be treated as "password protected".
	var sharePw any
	if err := db.QueryRow(`SELECT pw_hash FROM shares WHERE token='dropbox-share-token'`).Scan(&sharePw); err != nil {
		t.Fatalf("query share pw: %v", err)
	}
	if sharePw != nil {
		t.Fatalf("unprotected share has pw_hash %v, want NULL", sharePw)
	}

	// settings.json is never migrated — it must be untouched on disk.
	if _, err := os.Stat(filepath.Join(configDir, "settings.json")); err != nil {
		t.Fatalf("settings.json was removed by the migration: %v", err)
	}
}

func testSealerFromHex(t *testing.T, hexKey string) *crypt.Sealer {
	t.Helper()
	s, err := crypt.New(hexKey)
	if err != nil {
		t.Fatalf("crypt.New: %v", err)
	}
	return s
}
