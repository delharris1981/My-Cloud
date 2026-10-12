package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCreatesDirectoriesAndSecret(t *testing.T) {
	base := t.TempDir()
	cfgDir := filepath.Join(base, "config")
	dataDir := filepath.Join(base, "data")
	t.Setenv("MYCLOUD_CONFIG_DIR", cfgDir)
	t.Setenv("MYCLOUD_DATA_DIR", dataDir)
	t.Setenv("MYCLOUD_PORT", "9999")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Port != 9999 {
		t.Fatalf("port: got %d", cfg.Port)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "users")); err != nil {
		t.Fatalf("users dir not created: %v", err)
	}
	// secret.key is the encryption root; an absent one is a hard failure later.
	if len(cfg.Secret) < 32 {
		t.Fatalf("secret too short: %q", cfg.Secret)
	}
	if _, err := os.Stat(filepath.Join(cfgDir, "secret.key")); err != nil {
		t.Fatalf("secret.key not written: %v", err)
	}
	// settings.json should exist so operators can find and edit it.
	if _, err := os.Stat(cfg.SettingsPath()); err != nil {
		t.Fatalf("settings.json not written: %v", err)
	}
}

func TestLoadRegeneratesShortSecret(t *testing.T) {
	base := t.TempDir()
	cfgDir := filepath.Join(base, "config")
	t.Setenv("MYCLOUD_CONFIG_DIR", cfgDir)
	t.Setenv("MYCLOUD_DATA_DIR", filepath.Join(base, "data"))
	// A truncated write from an interrupted first boot. An empty key would
	// make every sealed value forgeable, so it must be replaced.
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "secret.key"), []byte("abc"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Secret) < 32 {
		t.Fatalf("short secret was not regenerated: %q", cfg.Secret)
	}
}

func TestLoadPreservesExistingSecret(t *testing.T) {
	base := t.TempDir()
	cfgDir := filepath.Join(base, "config")
	dataDir := filepath.Join(base, "data")
	t.Setenv("MYCLOUD_CONFIG_DIR", cfgDir)
	t.Setenv("MYCLOUD_DATA_DIR", dataDir)
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const existing = "0123456789abcdef0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(filepath.Join(cfgDir, "secret.key"), []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Secret != existing {
		t.Fatal("regenerated a valid secret; this would orphan every sealed value")
	}
}

func TestSettingsMergeKeepsDefaultsForAbsentKeys(t *testing.T) {
	base := t.TempDir()
	cfgDir := filepath.Join(base, "config")
	t.Setenv("MYCLOUD_CONFIG_DIR", cfgDir)
	t.Setenv("MYCLOUD_DATA_DIR", filepath.Join(base, "data"))
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A partial file, as an older version would have written. Decoding this
	// into a struct would zero every absent field and silently reset the site
	// name and session length.
	if err := os.WriteFile(filepath.Join(cfgDir, "settings.json"),
		[]byte(`{"siteName":"Home Cloud"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Settings.SiteName != "Home Cloud" {
		t.Fatalf("siteName not honoured: %q", cfg.Settings.SiteName)
	}
	if cfg.Settings.SessionDays != 30 {
		t.Fatalf("absent key did not keep its default: sessionDays=%d", cfg.Settings.SessionDays)
	}
	if cfg.Settings.TrashRetentionDays != 30 {
		t.Fatalf("absent key did not keep its default: trashRetentionDays=%d", cfg.Settings.TrashRetentionDays)
	}
	if !cfg.Settings.AllowPublicShares {
		t.Fatal("absent allowPublicShares did not keep its true default")
	}
}

func TestCorruptSettingsFallsBackToDefaults(t *testing.T) {
	base := t.TempDir()
	cfgDir := filepath.Join(base, "config")
	t.Setenv("MYCLOUD_CONFIG_DIR", cfgDir)
	t.Setenv("MYCLOUD_DATA_DIR", filepath.Join(base, "data"))
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "settings.json"), []byte("{oops"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("a corrupt settings.json must not crash the server: %v", err)
	}
	if cfg.Settings.SiteName != "My Cloud" {
		t.Fatalf("expected default site name, got %q", cfg.Settings.SiteName)
	}
	// The bad file is kept for the human who typed it.
	matches, _ := filepath.Glob(filepath.Join(cfgDir, "settings.json.corrupt-*"))
	if len(matches) == 0 {
		t.Fatal("corrupt settings.json was not quarantined")
	}
}

func TestSanitiseClampsDestructiveValues(t *testing.T) {
	s := Sanitise(Settings{
		SiteName:           "  ",
		DefaultQuotaMB:     -5,
		SessionDays:        0,
		TrashRetentionDays: -10,
	})
	if s.SiteName != "My Cloud" {
		t.Fatalf("blank site name not defaulted: %q", s.SiteName)
	}
	// A negative quota would reject every upload.
	if s.DefaultQuotaMB != 0 {
		t.Fatalf("negative quota not clamped: %d", s.DefaultQuotaMB)
	}
	// A zero session length would make every session instantly invalid.
	if s.SessionDays != 30 {
		t.Fatalf("sessionDays not repaired: %d", s.SessionDays)
	}
	// A negative retention would put the purge cutoff in the future and wipe
	// all trash.
	if s.TrashRetentionDays != 0 {
		t.Fatalf("negative retention not clamped: %d", s.TrashRetentionDays)
	}
}

func TestUserDirsMatchNodeLayout(t *testing.T) {
	base := t.TempDir()
	cfg := &Config{DataDir: base}
	baseDir, files, trash, thumbs := cfg.UserDirs("alice")
	if baseDir != filepath.Join(base, "users", "alice") {
		t.Fatalf("base dir changed: %q", baseDir)
	}
	if files != filepath.Join(baseDir, "files") || trash != filepath.Join(baseDir, "trash") || thumbs != filepath.Join(baseDir, "thumbs") {
		t.Fatal("user directory layout diverges from the Node version; an existing /data volume would break")
	}
}
