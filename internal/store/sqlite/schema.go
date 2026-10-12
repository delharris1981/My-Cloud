package sqlite

// SchemaVersion is the current expected value of schema_meta.version. Bump it
// when adding a migration to migrations below.
const SchemaVersion = 1

// schemaSQL is the full schema from docs/plans/sqlite-schema.md.
//
// Scope, unchanged from the plan: SQLite holds credentials and shares ONLY.
// No table holds a file's bytes, path, size, or per-file metadata — the users'
// data stays browseable with any other tool.
const schemaSQL = `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_meta (
  key   TEXT PRIMARY KEY,       -- 'version'
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  username            TEXT PRIMARY KEY,
  pw_hash             TEXT NOT NULL,   -- PHC: $argon2id$… (or legacy $2a$ on first login)
  is_admin            INTEGER NOT NULL DEFAULT 0,
  quota_mb            INTEGER,          -- NULL = unlimited
  created_at          INTEGER NOT NULL, -- unix millis
  password_changed_at INTEGER NOT NULL
);

-- Opaque session cookies. Only the SHA-256 of the token is stored, so a DB
-- leak does not yield usable cookies. Replaces the stateless HMAC tokens.
CREATE TABLE IF NOT EXISTS sessions (
  id           TEXT PRIMARY KEY,  -- sha256(token), hex. NOT the token itself
  username     TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  created_at   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,  -- sliding expiry
  expires_at   INTEGER NOT NULL,
  csrf_secret  TEXT NOT NULL,
  user_agent   TEXT,
  ip           TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

-- WebDAV/Basic auth. Same verifier format as pw_hash so both live in one
-- verification path.
CREATE TABLE IF NOT EXISTS app_passwords (
  id         TEXT PRIMARY KEY,
  username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  label      TEXT NOT NULL,
  pw_hash    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used  INTEGER
);
CREATE INDEX IF NOT EXISTS idx_apppw_user ON app_passwords(username);

CREATE TABLE IF NOT EXISTS totp (
  username  TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
  secret    BLOB NOT NULL,   -- sealed
  pending   BLOB,            -- sealed: staged secret before confirmation
  enabled   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_codes (
  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,  -- bcrypt, as today — these are low-entropy
  used_at  INTEGER          -- set on consumption; kept for audit, never reused
);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(username);

CREATE TABLE IF NOT EXISTS passkeys (
  credential_id BLOB PRIMARY KEY,  -- sealed raw ID
  username      TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  public_key    BLOB NOT NULL,     -- sealed COSE key
  sign_count    INTEGER NOT NULL DEFAULT 0,
  aaguid        BLOB,
  transports    TEXT,
  backed_up     INTEGER NOT NULL DEFAULT 0,  -- BE/BS flags
  uv            INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  last_used     INTEGER,
  label         TEXT
);
CREATE INDEX IF NOT EXISTS idx_passkeys_user ON passkeys(username);

CREATE TABLE IF NOT EXISTS shares (
  token        TEXT PRIMARY KEY,  -- 16 random bytes, base64url (as today)
  owner        TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  pw_hash      TEXT,              -- bcrypt, nullable
  expires_at   INTEGER,           -- NULL = never
  allow_upload INTEGER NOT NULL DEFAULT 0,
  downloads    INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_shares_owner ON shares(owner);

-- One row per shared item. A multi-selection share has many rows sharing a
-- token; a single-file share has exactly one.
CREATE TABLE IF NOT EXISTS share_items (
  token      TEXT NOT NULL REFERENCES shares(token) ON DELETE CASCADE,
  ordinal    INTEGER NOT NULL,   -- preserves selection order
  path       TEXT NOT NULL,       -- relative to owner's files root, never absolute
  is_dir     INTEGER NOT NULL,
  PRIMARY KEY (token, ordinal)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS audit_log (
  id        INTEGER PRIMARY KEY,
  at        INTEGER NOT NULL,
  username  TEXT,
  action    TEXT NOT NULL,   -- login.ok, login.fail, share.view, dav.auth, …
  detail    TEXT,            -- short, no secrets, no file contents
  ip        TEXT,
  ok        INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_audit_at   ON audit_log(at);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(username, at);

-- Triggers, not application code: two invariants are worth enforcing at the
-- database rather than trusting every future call site.
CREATE TRIGGER IF NOT EXISTS trg_sessions_purge AFTER UPDATE OF last_seen ON sessions
WHEN NEW.last_seen > NEW.expires_at
BEGIN DELETE FROM sessions WHERE id = NEW.id; END;

CREATE TRIGGER IF NOT EXISTS trg_shares_cascade AFTER DELETE ON shares
BEGIN DELETE FROM share_items WHERE token = OLD.token; END;
`
