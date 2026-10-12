# My Cloud — Go rewrite build plan

Full-feature, drop-in replacement of the Node/Express app. Flat filesystem, no
SQL for file data, secure user area that does not depend on JavaScript, htmx
frontend, better GUI.

Companion documents:
- `sqlite-recommendation.md` — why SQLite for credentials only
- `sqlite-schema.md` — the schema, encryption, and first-boot migration

---

## Ground rules

1. **Files stay flat.** No table, index, or cache holds a file's path, size, or
   metadata. Users' data remains browseable with any other tool.
2. **The server is the only authoriser.** Every mutation is a real form POST with
   a real session check. Nothing is authorised client-side.
3. **Every page works with JavaScript disabled.** htmx upgrades, it does not
   enable. This is testable — see "The no-JS guarantee".
4. **One way to touch the filesystem.** All user-data I/O goes through
   `vfs.Resolve`. No other package opens a path under `/data/users`.
5. **Stop rewriting JSON files.** Credentials and shares live in SQLite. Settings
   stay JSON because humans edit them by hand.

## Dependencies

| Module | Why |
|---|---|
| `modernc.org/sqlite` | pure-Go driver, keeps `CGO_ENABLED=0` static build |
| `golang.org/x/crypto` | argon2id, hkdf, bcrypt (for legacy hashes + recovery codes) |
| `go-webauthn/webauthn` + `fxamacker/cbor/v2` | passkeys — do not hand-roll the ceremony |
| `disintegration/imaging` | pure-Go thumbnails, no cgo |

TOTP is hand-rolled (~80 lines: HMAC-SHA1 + base32 + window check). WebDAV is
hand-rolled on `vfs`. Standard library routing via Go 1.22+ `ServeMux`.

---

## Package layout

```
cmd/my-cloud/main.go        wiring, PUID/PGID drop, graceful shutdown
internal/config/            env + settings.json (env overrides file)
internal/store/             atomic JSON store (settings only) — flock, tmp+rename
internal/store/sqlite/      //go:build sqlite — DB open, migrations, triggers
internal/auth/              users, password verify, sessions, CSRF, rate limit
internal/auth/passkey.go    go-webauthn wrapper
internal/auth/totp.go       hand-rolled TOTP
internal/vfs/               path confinement, quota, copy/move, trash, search
internal/vfs/securepath.go  THE choke point
internal/upload/            multipart + resumable chunk sessions
internal/thumb/             imaging + disk cache
internal/zipstream/         archive/zip -> io.Pipe, no temp file
internal/dav/               WebDAV verbs over vfs
internal/handlers/          htmx partials + minimal JSON API
internal/htmx/              response helpers (redirect-with-toast, fragments)
internal/middleware/        security headers, auth, CSRF, rate limit, request log
web/templates/              embed.FS
web/static/
```

---

## The load-bearing design: `securepath`

Both the browser and WebDAV take client-supplied paths. That is the entire
attack surface, and getting it wrong once compromises everything.

```go
// Resolve maps a client path to an absolute path inside root, or an error.
func (fs *FS) Resolve(clientPath string) (abs string, err error)
```

All rules enforced here and nowhere else:

- Strip leading slashes; `path.Clean`
- Empty or `.` resolves to root
- `filepath.Rel(root, abs)` must not begin with `..`
- `filepath.EvalSymlinks` on the **parent** must still land inside root — this is
  what stops a symlink planted inside a shared folder from becoming an escape
  hatch. `EvalSymlinks` fails on a not-yet-existing leaf, so resolve the parent.
- Reject NUL bytes and any path component > 255 bytes

Browser listing, WebDAV `PROPFIND`, download, upload, zip streaming, trash
restore, search, and thumbnails all funnel through this. Grep the tree for
`os.Open`, `os.Create`, `filepath.Join(...DATA_DIR` — every hit must be inside
`internal/vfs` or `internal/upload`, which calls `Resolve` first.

---

## Security posture

Beyond parity with the Node version:

| Area | Node (today) | Go rewrite |
|---|---|---|
| Passwords | bcrypt cost 10 | argon2id PHC; lazy-upgrade legacy bcrypt on login |
| Session token | 20 bytes, stateless HMAC | 32 bytes opaque, **SHA-256 at rest**, server-side, revocable |
| Logout | client-side only | deletes the session row |
| CSRF | none | synchroniser token per session, in every form |
| TOTP / passkey seeds | plaintext JSON | AES-256-GCM, HKDF subkeys from existing `secret.key` |
| Security headers | partial | full set incl. CSP without `unsafe-inline` |
| Audit log | none | append-only table: logins, failures, share views, DAV auth |

Sessions also gain "log out all devices" and a visible device list, which
stateless tokens could not provide.

Other details:
- `SameSite=Strict`, `Secure` when behind TLS, `HttpOnly` on the session cookie
- Per-IP **and** per-username login rate limits; constant-time everywhere
- `trust proxy` equivalent: default to loopback/linklocal only, override via env
- Password-protected share links must return identical errors for wrong
  password / expired / revoked — no existence oracle via status code or timing
- Constant dummy hash comparison on unknown usernames, so login timing does not
  enumerate accounts

---

## Frontend: htmx + html/template

Server-rendered Go templates, `htmx` vendored locally (no CDN). `public/app.js`
(1,558 lines) is deleted outright.

**Partial boundaries.** Every handler takes an optional `partial` query param and
renders a fragment rather than a full page. One handler, two render modes — no
duplicate template logic.

**Interactions:**
- File list: `hx-get` on navigation, `hx-push-url` so every view is a
  bookmarkable URL. Grid/list toggle, sort, multi-select kept in the query
  string (`selected` param) so state survives a reload and a shared link.
- Search: `hx-trigger="input changed delay:250ms, search"`
- Upload: `hx-encoding="multipart/form-data"` + `hx-indicator`; whole-folder via
  `webkitdirectory`. Resumable chunks need one ~60-line JS shim (`hx-put` with
  `Content-Range`); without JS it falls back to a plain single-request upload.
- Modals: `hx-boost` on links, `hx-target="#modal"`
- Toasts: `HX-Trigger: mycloud:toast` response header + ~20-line listener
- Session expiry: `HX-Trigger` pushes a redirect to `/login`

**The no-JS guarantee.** Every mutation is `<form method="post">` that works
standalone; htmx only intercepts to add progress and partial swaps. `hx-boost` on
navigation means browsing degrades to ordinary full page loads.

Acceptance test: load the app with JS blocked, and you can log in, browse,
upload, create a folder, rename, move, delete, restore from trash, create a share
link, and upload to a drop box. Only live search and multi-select degrade.

**Keep the PWA** — service worker and manifest survive, updated for htmx.

---

## Minimal JSON API

Not everything should become HTML. These stay JSON because WebDAV, the PWA, and
future clients need them, and because htmx cannot do range requests well:

- `GET /api/status`, `GET /api/auth/me`
- Resumable upload session lifecycle (create / status / chunk / complete)
- `GET /api/search` — used by the command palette
- WebDAV mount credentials

Everything else is htmx partials.

---

## Build order

Each step is independently shippable and verified before the next begins.

### 1. Foundation — store, config, skeleton
`internal/store` (atomic JSON, flock, corrupt-file quarantine), `internal/config`
(env + `settings.json`), `internal/store/sqlite` (open, WAL, PRAGMAs, migrations,
schema per `sqlite-schema.md`), `cmd/my-cloud/main.go`, security-header
middleware, healthcheck, graceful shutdown.

**Done when:** binary boots, creates an empty DB, `/api/status` answers, Docker
image builds, CI green.

### 2. First-boot migration
Idempotent, one transaction, `flock` on `/config/.migrate.lock`. Detect
`no schema_meta AND users.json exists`. Copy bcrypt and app-password hashes
verbatim, re-seal TOTP secrets, migrate `shares.json`, rename originals to
`.migrated.bak`. Sessions are not migrated — one forced re-login.

**Done when:** a populated `/config` from the running Node app opens correctly in
Go, with all users, quotas, shares, and TOTP enrolments intact.

### 3. Auth — the "secure user area" milestone
argon2id + bcrypt verify, sessions (opaque, hashed at rest, sliding expiry),
CSRF, rate limits, TOTP, app passwords, logout-all, setup wizard, login/2FA
templates.

**Done when:** the full login area is server-rendered and functional with JS
disabled. Audit log rows written.

### 4. `vfs` + `securepath`
Resolve, confinement, symlink handling, listing, download, mkdir, rename, move,
copy, delete, trash + restore + empty, search, quota with TTL cache.

**Done when:** a `securepath_test.go` table of traversal payloads all return
errors, including symlink-escape cases.

### 5. Upload
Multipart single-request, then resumable chunk sessions with `Content-Range`,
`.part` files, and cleanup of stale sessions. Quota enforced server-side.

### 6. htmx UI — the "better GUI" milestone
Templates, partials, file browser, grid/list, breadcrumbs, multi-select, modals,
toasts, styling. Delete `public/app.js`.

**Done when:** the no-JS acceptance test above passes.

### 7. Media
Thumbnails (`imaging`, disk cache in `/data/users/*/thumbs`), image/video/audio
previews with seeking, PDF, text editor, zip streaming via `io.Pipe`.

### 8. Shares
Authenticated management, public pages, password + expiry, drop-box upload,
per-item rows, download counter. No existence oracle.

### 9. WebDAV
Hand-rolled on `vfs`: `PROPFIND` (with depth), `PROPPATCH`, `MKCOL`, `MOVE`,
`COPY`, `LOCK`/`UNLOCK`, `PUT`, `DELETE`, `GET`, `HEAD`. Basic auth accepting
app passwords always, account password only when 2FA is off. Auth cache with
bounded size and TTL, as today.

**Done when:** mounts in Finder/Windows/rclone and round-trips files.

### 10. Passkeys
go-webauthn, `passkeys` table, registration + assertion, counter and
backup-state tracking. TOTP retained as a fallback method.

### 11. Packaging
Dockerfile (distroless/alpine, non-root, `HEALTHCHECK`), compose, Unraid template,
README rewrite, CI: build, `go vet`, tests, image publish.

---

## Strangler rollout

Run the Go server against the **same** `/config` and `/data` volumes as Node,
on a different port, read-only on `/config` to avoid two writers migrating at
once.

Verify before cutover:
- File listings and byte counts match at several depths
- Existing share links still resolve and download
- TOTP logins work (proves re-sealing round-tripped)
- Trash contents intact
- Zip download of a folder matches

Then: stop Node, start Go, `docker restart`, expect one re-login.

Keep `.migrated.bak` files. Rollback to Node is a `mv` away until you're satisfied.

---

## Risks

| Risk | Mitigation |
|---|---|
| `securepath` bypass somewhere | Single choke point; test table of traversal + symlink payloads; grep audit in CI |
| Migration loses data | Transactional, idempotent, originals renamed not deleted, verified side-by-side |
| Hand-rolled WebDAV edge cases | Test against real clients (rclone, Finder, `litmus`) during step 9 |
| htmx chunked-upload shim breaks | Plain upload is the fallback; both paths tested |
| Static binary grows (~10MB) | Accepted, in exchange for no cgo and single-file deploy |
| Passkey counter false-positives on some platforms | Counters advisory, log before rejecting; BS flags surfaced in UI |

## Explicitly deferred

- **xattr metadata** — WebDAV mtimes will reflect copy time on xfs/ext4. Real
  fix is contained to `internal/vfs`; add later if it matters.
- **Full-text content search** — filename search only, as today.
- **Multi-server / clustering** — single-node, single-writer. SQLite in WAL mode
  makes the constraint explicit rather than accidental.