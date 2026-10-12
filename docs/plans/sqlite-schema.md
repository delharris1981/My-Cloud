# SQLite schema design — My Cloud Go rewrite

> Design artifact. Companion to `sqlite-recommendation.md`. Not a build plan.

## Scope (from the agreed decision)

SQLite holds **credentials and shares only**. Everything else stays plain files:

| Stays on disk | Goes in SQLite |
|---|---|
| `/data/users/*/files` | accounts |
| `/data/users/*/trash` | sessions, app passwords |
| `/data/users/*/thumbs` | TOTP + passkey credentials |
| `/config/settings.json` (hand-editable) | share links + items |
| `/config/secret.key` | audit log |

**No table anywhere holds a file's bytes, path, or per-file metadata.** That was the
original promise of the project and this schema does not erode it.

---

## Master key

`/config/secret.key` already exists (48 hex chars = 24 bytes of entropy, actually
96 chars = 48 bytes) and already survives restarts. Since sessions are now opaque
server-side tokens, nothing signs with it any more, so it is repurposed as the
**encryption-at-rest root**.

Derive purpose-specific subkeys with HKDF-SHA256 (`golang.org/x/crypto/hkdf`):

```
root         = hex.Decode(secret.key)                  // existing file, unchanged
kSecrets     = HKDF(root, info="mycloud:v1:secrets")    // TOTP seeds, recovery codes
kPasskeys    = HKDF(root, info="mycloud:v1:passkeys")   // WebAuthn credential IDs
kSharePw     = HKDF(root, info="mycloud:v1:sharepw")    // share-link passwords
```

One leaked subkey cannot decrypt another table. Losing `secret.key` means
re-enrolling all 2FA and breaking password-protected shares — same blast radius
as losing it today, so no new operational burden.

**Record envelope** — AES-256-GCM, fresh 12-byte nonce per record, AAD = table
name + primary key so a row cannot be moved between tables or users:

```go
type sealed struct {
    Nonce []byte // 12
    CT    []byte // ciphertext || tag
}
```

Reuse the existing atomic-write store's discipline for `secret.key`: tmp file +
`fs.Rename`.

---

## Schema

```sql
PRAGMA journal_mode = WAL;      -- concurrent readers while a writer commits
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;     -- backup/copy tools hold the lock briefly
PRAGMA synchronous = NORMAL;    -- safe under WAL, avoids an fsync per commit

CREATE TABLE schema_meta (
  key   TEXT PRIMARY KEY,       -- 'version'
  value TEXT NOT NULL
);

CREATE TABLE users (
  username            TEXT PRIMARY KEY,
  pw_hash             TEXT NOT NULL,   -- PHC: $argon2id$… (or legacy $2a$ on first login)
  is_admin            INTEGER NOT NULL DEFAULT 0,
  quota_mb            INTEGER,          -- NULL = unlimited
  created_at          INTEGER NOT NULL, -- unix millis, matches existing JSON
  password_changed_at INTEGER NOT NULL  -- invalidates sessions issued before
);

-- Opaque session cookies. Only the SHA-256 of the token is stored, so a DB
-- leak does not yield usable cookies. Replaces the stateless HMAC tokens.
CREATE TABLE sessions (
  id           TEXT PRIMARY KEY,  -- sha256(token), hex. NOT the token itself
  username     TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  created_at   INTEGER NOT NULL,
  last_seen    INTEGER NOT NULL,  -- sliding expiry
  expires_at   INTEGER NOT NULL,
  csrf_secret  TEXT NOT NULL,     -- synchroniser token, per session
  user_agent   TEXT,
  ip           TEXT
);
CREATE INDEX idx_sessions_user    ON sessions(username);
CREATE INDEX idx_sessions_expires ON sessions(expires_at);  -- sweep query

-- WebDAV/Basic auth. Same verifier format as pw_hash so both live in one
-- verification path.
CREATE TABLE app_passwords (
  id         TEXT PRIMARY KEY,
  username   TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  label      TEXT NOT NULL,
  pw_hash    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_used  INTEGER
);
CREATE INDEX idx_apppw_user ON app_passwords(username);

CREATE TABLE totp (
  username  TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
  secret    BLOB NOT NULL,   -- sealed
  pending   BLOB,            -- sealed: staged secret before confirmation
  enabled   INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
);

CREATE TABLE recovery_codes (
  username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,  -- bcrypt, as today — these are low-entropy
  used_at  INTEGER          -- set on consumption; kept for audit, never reused
);
CREATE INDEX idx_recovery_user ON recovery_codes(username);

CREATE TABLE passkeys (
  credential_id BLOB PRIMARY KEY,  -- sealed raw ID
  username      TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  public_key    BLOB NOT NULL,     -- sealed COSE key
  sign_count    INTEGER NOT NULL DEFAULT 0,
  aaguid        BLOB,
  transports    TEXT,
  backed_up     INTEGER NOT NULL DEFAULT 0,  -- BE/BS flags, watch for cloning
  uv            INTEGER NOT NULL DEFAULT 0,
  created_at    INTEGER NOT NULL,
  last_used     INTEGER,
  label         TEXT
);
CREATE INDEX idx_passkeys_user ON passkeys(username);

CREATE TABLE shares (
  token        TEXT PRIMARY KEY,  -- 16 random bytes, base64url (as today)
  owner        TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
  pw_hash      TEXT,              -- bcrypt, nullable
  expires_at   INTEGER,           -- NULL = never
  allow_upload INTEGER NOT NULL DEFAULT 0,
  downloads    INTEGER NOT NULL DEFAULT 0,
  created_at   INTEGER NOT NULL
);
CREATE INDEX idx_shares_owner ON shares(owner);

-- One row per shared item. A multi-selection share has many rows sharing a token;
-- a single-file share has exactly one. Shares the same PRAGMA/WAL benefits as the
-- rest — the frequently-bumped `downloads` counter no longer rewrites a JSON file.
CREATE TABLE share_items (
  token      TEXT NOT NULL REFERENCES shares(token) ON DELETE CASCADE,
  ordinal    INTEGER NOT NULL,   -- preserves selection order
  path       TEXT NOT NULL,       -- relative to owner's files root, never absolute
  is_dir     INTEGER NOT NULL,
  PRIMARY KEY (token, ordinal)
) WITHOUT ROWID;

CREATE TABLE audit_log (
  id        INTEGER PRIMARY KEY,
  at        INTEGER NOT NULL,
  username  TEXT,
  action    TEXT NOT NULL,   -- login.ok, login.fail, share.view, dav.auth, …
  detail    TEXT,            -- short, no secrets, no file contents
  ip        TEXT,
  ok        INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX idx_audit_at   ON audit_log(at);
CREATE INDEX idx_audit_user ON audit_log(username, at);
```

`WITHOUT ROWID` on `share_items` is deliberate — the natural composite key is the
primary key, so a separate index would be pure overhead.

---

## Notes on specific choices

**Integer timestamps, not `INTEGER` seconds.** Millis, matching what `users.json`
already stores, so the first-boot migration is a straight copy.

**Triggers, not application code.** Two invariants are worth enforcing at the
database rather than trusting every future call site:

```sql
CREATE TRIGGER trg_sessions_purge AFTER UPDATE OF last_seen ON sessions
WHEN NEW.last_seen > NEW.expires_at
BEGIN DELETE FROM sessions WHERE id = NEW.id; END;

-- Refuse to orphan a credential when a share is deleted.
CREATE TRIGGER trg_shares_cascade AFTER DELETE ON shares
BEGIN DELETE FROM share_items WHERE token = OLD.token; END;
```

**Quota stays out of SQL.** Per-user usage is derived from disk and cached in
memory with a short TTL, as the Node version does. A `usage_bytes` column would
drift the moment a file is changed outside the app.

**`sign_count` must increase.** go-webauthn rejects a non-increasing counter
against a stored credential — that is the cloned-authenticator signal. Persisting
it is what makes the check work across restarts.

**`recovery_codes` are bcrypt, not argon2.** They are 8–10 chars of low entropy
and are checked in a loop; the cost parameter is a DoS knob on that path, not a
storage concern. Argon2 at interactive cost would be the wrong trade here.

---

## First-boot migration (drop-in requirement)

The Go binary must open an existing `/config` untouched by the Node version.

```
no schema_meta row AND /config/users.json exists  →  migrate
schema_meta.version < N                            →  migrate up
otherwise                                          →  open
```

Idempotent, runs in one transaction, and takes an `flock` on
`/config/.migrate.lock` so two containers can never race it.

Mapping:

| `users.json` | SQL |
|---|---|
| `username` | `users.username` |
| `passwordHash` | `users.pw_hash` (verbatim — still `$2a$`) |
| `isAdmin` | `users.is_admin` |
| `quotaMB` | `users.quota_mb` (`null` = unlimited) |
| `createdAt`, `passwordChangedAt` | verbatim |
| `totpSecret`, `totpPending`, `recovery[]` | `totp`, `recovery_codes` — **re-sealed** |
| `appPasswords[]` | `app_passwords` (verbatim hashes) |

`shares.json` → `shares` + `share_items`. `settings.json` is **never migrated**;
it stays JSON and is read as-is.

The original `users.json` / `shares.json` are renamed to `.migrated.bak`, not
deleted, so a rollback to Node is still possible during the side-by-side
comparison.

**Sessions are not migrated.** Opaque SHA-256-at-rest tokens replace stateless
HMAC tokens; the old ones cannot be honoured. Cost is one forced re-login per
user, once.

**Lazy password upgrade.** `verifyPassword` accepts either format. On a successful
bcrypt verification during login, re-hash with argon2id and write the new row.
No forced reset, and `pw_hash` cost can be raised later transparently.

---

## Optional at build time

`internal/store/sqlite` behind `//go:build sqlite` with the JSON-store fallback in
`internal/store/json`. Driver selection via build tags, so `CGO_ENABLED=0`
pure-Go builds stay available by picking `modernc.org/sqlite`; the tag exists so
the no-DB story survives as a first-class option rather than a fork.

### Dependencies this adds
- `modernc.org/sqlite` — pure Go, keeps the static build (~10MB binary)
- `golang.org/x/crypto` — already agreed (argon2id, hkdf, bcrypt for migration)
- `fxamacker/cbor/v2` + `go-webauthn/webauthn` — passkeys only