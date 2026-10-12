// Package config resolves runtime configuration from the environment and
// settings.json, with the environment taking precedence.
//
// settings.json is deliberately NOT migrated from the Node version: it is the
// one file a human edits by hand, and its format is unchanged.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/derek/my-cloud/internal/store"
)

// Settings mirrors the defaults in the Node config.js exactly. Field names
// match the JSON so the file stays hand-editable and compatible.
type Settings struct {
	SiteName           string `json:"siteName"`
	AllowSignup        bool   `json:"allowSignup"`
	DefaultQuotaMB     int    `json:"defaultQuotaMB"` // 0 = unlimited
	SessionDays        int    `json:"sessionDays"`
	TrashRetentionDays int    `json:"trashRetentionDays"`
	AllowPublicShares  bool   `json:"allowPublicShares"`
}

// DefaultSettings returns the built-in defaults.
func DefaultSettings() Settings {
	return Settings{
		SiteName:           "My Cloud",
		AllowSignup:        false,
		DefaultQuotaMB:     0,
		SessionDays:        30,
		TrashRetentionDays: 30,
		AllowPublicShares:  true,
	}
}

// Config is the fully-resolved runtime configuration.
type Config struct {
	ConfigDir string
	DataDir   string
	Port      int
	Settings  Settings

	// Secret is the hex contents of secret.key, the root key for encryption
	// at rest. Load guarantees it is present and at least 32 bytes.
	Secret string

	// ForceSecureCookie mirrors MYCLOUD_FORCE_SECURE_COOKIE, for operators
	// terminating TLS at a proxy that does not forward X-Forwarded-Proto.
	ForceSecureCookie bool

	settingsPath string
	settings     *store.JSON
}

// SettingsPath is the on-disk path of settings.json.
func (c *Config) SettingsPath() string { return c.settingsPath }

// Load reads configuration, creating config/data directories, secret.key, and
// settings.json if they do not exist.
//
// Secret handling follows the Node version: a missing, empty, or suspiciously
// short secret.key is regenerated. An empty root key would make every sealed
// value trivially forgeable, so failing closed here matters.
func Load() (*Config, error) {
	cfg := &Config{
		ConfigDir:         env("MYCLOUD_CONFIG_DIR", "/config"),
		DataDir:           env("MYCLOUD_DATA_DIR", "/data"),
		Port:              envInt("MYCLOUD_PORT", 8686),
		ForceSecureCookie: envBool("MYCLOUD_FORCE_SECURE_COOKIE"),
	}

	// Both roots must exist before anything writes into them: secret.key and
	// settings.json land in ConfigDir, user data under DataDir/users.
	if err := os.MkdirAll(cfg.ConfigDir, 0o755); err != nil {
		return nil, fmt.Errorf("config: create config dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "users"), 0o755); err != nil {
		return nil, fmt.Errorf("config: create data dir: %w", err)
	}

	secret, err := loadOrCreateSecret(cfg.ConfigDir)
	if err != nil {
		return nil, err
	}
	cfg.Secret = secret

	cfg.settingsPath = filepath.Join(cfg.ConfigDir, "settings.json")
	cfg.settings = store.NewJSON(cfg.settingsPath)
	if err := cfg.loadSettings(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func loadOrCreateSecret(dir string) (string, error) {
	path := filepath.Join(dir, "secret.key")
	secret := ""
	if b, err := os.ReadFile(path); err == nil {
		secret = strings.TrimSpace(string(b))
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("config: read secret.key: %w", err)
	}
	if len(secret) < 32 {
		b, err := randomHex(48)
		if err != nil {
			return "", err
		}
		if err := writeSecretAtomic(path, b); err != nil {
			return "", err
		}
		secret = b
	}
	return secret, nil
}

// writeSecretAtomic uses a 0600 temp file, fsync, then rename: a crash can
// never leave a truncated key that would later be accepted as valid.
func writeSecretAtomic(path, value string) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("config: create secret temp: %w", err)
	}
	if _, err := f.WriteString(value); err != nil {
		f.Close()
		return fmt.Errorf("config: write secret: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("config: fsync secret: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("config: close secret: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("config: rename secret: %w", err)
	}
	return nil
}

// loadSettings merges settings.json over the defaults. A corrupt file falls
// back to defaults rather than crashing, matching the Node behaviour.
func (c *Config) loadSettings() error {
	c.Settings = DefaultSettings()
	b, err := os.ReadFile(c.settingsPath)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Fresh install: write the defaults so the file is discoverable.
		return c.SaveSettings(c.Settings)
	case err != nil:
		return fmt.Errorf("config: read settings: %w", err)
	}
	// Merge onto the defaults key-by-key rather than decoding into a struct:
	// unmarshalling into Settings would overwrite every default with the Go
	// zero value for any key absent from the file, so a settings.json written
	// by an older version would silently reset the site name to "" and the
	// session length to 0.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		// Quarantine rather than silently discard: a human may have typo'd it
		// and will want it back.
		if q, qerr := store.Quarantine(c.settingsPath); qerr == nil {
			fmt.Fprintf(os.Stderr, "config: settings.json was corrupt, moved to %s; using defaults\n", q)
		}
		return c.SaveSettings(c.Settings)
	}
	d := DefaultSettings()
	if _, ok := raw["siteName"]; ok {
		json.Unmarshal(raw["siteName"], &d.SiteName)
	}
	if _, ok := raw["allowSignup"]; ok {
		json.Unmarshal(raw["allowSignup"], &d.AllowSignup)
	}
	if _, ok := raw["defaultQuotaMB"]; ok {
		json.Unmarshal(raw["defaultQuotaMB"], &d.DefaultQuotaMB)
	}
	if _, ok := raw["sessionDays"]; ok {
		json.Unmarshal(raw["sessionDays"], &d.SessionDays)
	}
	if _, ok := raw["trashRetentionDays"]; ok {
		json.Unmarshal(raw["trashRetentionDays"], &d.TrashRetentionDays)
	}
	if _, ok := raw["allowPublicShares"]; ok {
		json.Unmarshal(raw["allowPublicShares"], &d.AllowPublicShares)
	}
	c.Settings = d
	return nil
}

// SaveSettings persists settings atomically and updates the in-memory copy.
func (c *Config) SaveSettings(s Settings) error {
	s = Sanitise(s)
	if err := c.settings.Write(s); err != nil {
		return err
	}
	c.Settings = s
	return nil
}

// Sanitise clamps values that would otherwise be destructive. A negative
// retention would put the purge cutoff in the future and wipe all trash; a
// negative quota would reject every upload. These match the Node clamps.
func Sanitise(s Settings) Settings {
	if strings.TrimSpace(s.SiteName) == "" {
		s.SiteName = "My Cloud"
	}
	s.SiteName = strings.TrimSpace(s.SiteName)
	if len(s.SiteName) > 60 {
		s.SiteName = s.SiteName[:60]
	}
	if s.DefaultQuotaMB < 0 {
		s.DefaultQuotaMB = 0
	}
	if s.SessionDays < 1 {
		s.SessionDays = 30
	}
	if s.TrashRetentionDays < 0 {
		s.TrashRetentionDays = 0
	}
	return s
}

// SessionDuration is the session lifetime from settings.
func (c *Config) SessionDuration() time.Duration {
	return time.Duration(c.Settings.SessionDays) * 24 * time.Hour
}

// DBPath is the SQLite database location.
func (c *Config) DBPath() string { return filepath.Join(c.ConfigDir, "my-cloud.db") }

// UsersDir is the root of all user data.
func (c *Config) UsersDir() string { return filepath.Join(c.DataDir, "users") }

// UserDirs returns the per-user directory layout, matching the Node
// userDirs() so an existing /data volume keeps working untouched.
func (c *Config) UserDirs(username string) (base, files, trash, thumbs string) {
	base = filepath.Join(c.UsersDir(), username)
	return base,
		filepath.Join(base, "files"),
		filepath.Join(base, "trash"),
		filepath.Join(base, "thumbs")
}

// randomHex returns n random bytes, hex-encoded — the same shape the Node
// version writes for secret.key (crypto.randomBytes(48).toString('hex')).
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("config: read random: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	}
	return false
}
