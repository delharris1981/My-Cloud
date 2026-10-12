package auth

import (
	"database/sql"

	// Registered for the side effect of registering the "sqlite" driver.
	_ "modernc.org/sqlite"
)

// openSchema opens a database and applies the full schema. It duplicates the
// DDL rather than importing internal/store/sqlite, because that package depends
// on crypt (for sealing migrated secrets) and the dependency would otherwise
// point back at auth.
//
// The production schema lives in one place; this file exists only so auth
// tests can build a real database without an import cycle. A schema drift
// between the two is caught by the store/sqlite test suite, which exercises the
// real DDL.
func openSchema(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(authTestSchema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// authTestSchema mirrors the tables auth touches. Columns and constraints
// match internal/store/sqlite/schema.go.
const authTestSchema = `
CREATE TABLE users (
  username            TEXT PRIMARY KEY,
  pw_hash             TEXT NOT NULL,
  is_admin            INTEGER NOT NULL DEFAULT 0,
  quota_mb            INTEGER,
  created_at          INTEGER NOT NULL,
  password_changed_at INTEGER NOT NULL
);

CREATE TABLE sessions (
  id           TEXT PRIMARY KEY,
  username     TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  created_at   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL,
  csrf_secret  TEXT NOT NULL,
  user_agent   TEXT,
  ip           TEXT
);
CREATE INDEX idx_sessions_user ON sessions(username);

CREATE TABLE app_passwords (
  id         TEXT PRIMARY KEY,
  username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  label      TEXT NOT NULL,
  pw_hash    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used  INTEGER
);

CREATE TABLE totp (
  username  TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
  secret    BLOB,
  pending   BLOB,
  enabled   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE recovery_codes (
  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  used_at  INTEGER
);

CREATE TABLE passkeys (
  credential_id BLOB PRIMARY KEY,
  username      TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  public_key    BLOB NOT NULL,
  sign_count    INTEGER NOT NULL DEFAULT 0,
  aaguid        BLOB,
  transports    TEXT,
  backed_up     INTEGER NOT NULL DEFAULT 0,
  uv            INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  last_used     INTEGER,
  label         TEXT
);

CREATE TABLE audit_log (
  id        INTEGER PRIMARY KEY,
  at        INTEGER NOT NULL,
  username  TEXT,
  action    TEXT NOT NULL,
  detail    TEXT,
  ip        TEXT,
  ok        INTEGER NOT NULL DEFAULT 1
);

CREATE TRIGGER trg_sessions_purge AFTER UPDATE OF last_seen ON sessions
WHEN NEW.last_seen > NEW.expires_at
BEGIN DELETE FROM sessions WHERE id = NEW.id; END;
`
