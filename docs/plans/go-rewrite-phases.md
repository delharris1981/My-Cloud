# My Cloud — Go rewrite, phased delivery

Phasing view of `go-rewrite-plan.md`. The plan's 11 build steps are unchanged and
remain the unit of work; this document only groups them into four delivery
phases, each with an exit gate.

Read the plan for the design decisions — `securepath`, the security posture, the
no-JS guarantee. This file answers only: *what order, and what must be true
before we move on.*

---

## Phase 1 — Foundations (steps 1–2)
**Outcome: a Go binary that boots, owns a database, and can adopt the Node app's data.**

| Step | Deliverable |
| --- | --- |
| 1 | `internal/store` (atomic JSON, flock, corrupt-file quarantine), `internal/config`, `internal/store/sqlite` (WAL, PRAGMAs, migrations), `cmd/my-cloud/main.go`, security-header middleware, healthcheck, graceful shutdown |
| 2 | Idempotent first-boot migration off `users.json` / `shares.json` / `secret.key`, originals renamed `.migrated.bak` |

**Exit gate:** binary boots and creates an empty DB; `/api/status` answers;
Docker image builds and CI is green; a populated `/config` from the running Node
app opens correctly in Go with users, quotas, shares, and TOTP enrolments intact.

**Why grouped:** migration is worthless without the schema it writes into, and
neither is testable without the server. The pair is one unit of "the Go app can
exist alongside Node" — which is the precondition for every later phase.

---

## Phase 2 — Secure core (steps 3–5)
**Outcome: the "secure user area" milestone, plus the filesystem layer every
later phase sits on.**

**Status: engine complete, HTTP surface partial.** Packages `internal/auth`,
`internal/vfs`, `internal/upload` are done and tested; the auth endpoints are
wired in `internal/server`. See "Not yet met" below.

| Step | Deliverable |
| --- | --- |
| 3 | argon2id + bcrypt verify, opaque server-side sessions, CSRF, rate limits, TOTP, app passwords, logout-all, setup wizard |
| 4 | `vfs` + `securepath`: Resolve, confinement, symlink handling, listing, download, mkdir/rename/move/copy/delete, trash + restore + empty, search, quota |
| 5 | Upload: multipart single-request, then resumable chunk sessions with `Content-Range`, `.part` files, stale-session cleanup |

**Exit gate:** the full login area is server-rendered and functional with JS
disabled, and audit-log rows are written; a `securepath_test.go` table of
traversal payloads — including symlink-escape cases — all return errors; uploads
work both ways with quota enforced server-side.

**Why grouped:** `securepath` is the single choke point for the entire attack
surface. Nothing in phases 3 or 4 is allowed to open a path under `/data/users`
except through it, so it must be landed and proven *before* the UI, shares, and
WebDAV start calling it. Auth ships with it because the file handlers are all
session-gated anyway.

### Not yet met — carried into phase 3

The engine work is done and proven, but two halves of the gate remain, and both
belong to step 6 (the htmx UI) rather than to this phase:

- **No server-rendered templates.** The auth endpoints work and are verified
  over HTTP, but they return JSON. The no-JS acceptance test cannot pass until
  the templates land. This is the bulk of what step 3 still owes.
- **No file/trash HTTP handlers.** `vfs` and `upload` are complete and tested,
  but nothing is mounted at `/api/files`. Step 4's HTTP surface is deferred to
  the same pass that builds the file browser, so the handler and partial
  boundaries are decided together rather than twice.

Also outstanding, smaller: no self-service "regenerate recovery codes" endpoint,
and `vfs` has no trash operations yet (delete is permanent; trash arrives with
the UI). WebDAV `LOCK`/`UNLOCK` remain step 9.

### Verified during this phase

- TOTP secrets re-sealed by the migration decrypt correctly: a code generated
  from the pre-migration secret still authenticates after cutover.
- Passwords verified against a real bcrypt hash migrate to argon2id on first
  login with no forced reset.
- Wrong-password and unknown-user responses are byte-identical, so the status
  code does not enumerate accounts.
- Logout and "log out all devices" genuinely revoke; the old cookie returns 401.
- CSRF is enforced on every mutation, via form field and via header.

---

## Phase 3 — Experience (steps 6–8)
**Outcome: the "better GUI" milestone — the product a user actually touches.**

**Status: engine complete, exit gate met.** The no-JS acceptance walkthrough is
now an automated test (`TestNoJSAcceptance`), so the gate cannot silently
regress. `public/app.js` is deleted; the Go server embeds its own assets.

| Step | Deliverable |
| --- | --- |
| 6 | htmx UI: templates, partials, file browser, grid/list, breadcrumbs, multi-select, toasts, styling |
| 7 | Media: previews, PDF, text editor, zip streaming. **Thumbnails deferred** — see below |
| 8 | Shares: management, public pages, password + expiry, drop-box upload, per-item rows, download counter |

**Exit gate:** the no-JS acceptance test passes — with JS blocked you can log
in, browse, upload, create a folder, rename, move, delete, restore from trash,
create a share link, and upload to a drop box; only live search and multi-select
degrade.

**Why grouped:** this is the first phase a user can be shown. Steps 6–8 all
render through the same partial/htmx conventions, so they are one coherent UI
pass rather than three separate ones. No new security surface enters here —
`securepath` was already proven in phase 2, and shares inherit its guarantee.

### Also delivered here (phase 2 debt)

- **Server-rendered auth templates** — login, 2FA, and setup pages, with a
  pre-session CSRF token for the login form.
- **File and trash HTTP handlers** — list, download, mkdir, rename, move, copy,
  delete, search, usage, content read/write, upload, and the full trash cycle.
- **`vfs` trash** — delete-to-trash with a sidecar recording the original path,
  restore that never overwrites a newer file, purge, empty, and retention.

### Not delivered — deferred out of this phase

- **Thumbnails (part of step 7).** The `imaging` dependency and disk cache were
  not added. Thumbnails are a performance feature with no security surface and
  no bearing on the exit gate; they are a self-contained addition and should
  land with the rest of step 7.
- **Modals and drag-drop move.** Drag-drop *upload* works; dragging a file to
  move it does not. Both are htmx conveniences that degrade gracefully.
- **Video/PDF player UI.** Range requests are served correctly by
  `http.ServeContent`; there is no bespoke player.

### Verified during this phase

- The full no-JS journey (setup → login → browse → upload → mkdir → rename →
  download → delete → restore → share → drop-box upload) passes as a test.
- Every mutation refuses to run without a CSRF token, including logout.
- One user cannot list, download, or delete another user's files.
- Unknown, expired, revoked, and password-wrong share tokens all return an
  identical response body, so the endpoint is not a token oracle.
- A share's bcrypt verifier never appears in any API response.

## Phase 4 — Interop and ship (steps 9–11)
**Outcome: a drop-in replacement, packaged and ready for cutover.**

**Status: complete.** Packages `internal/dav`, passkeys in `internal/auth`, and
the packaging set. WebDAV verified against real rclone; a scripted conformance
run is wired into CI.

| Step | Deliverable |
| --- | --- |
| 9 | WebDAV on `vfs`: all eleven verbs, basic auth for app passwords, bounded auth cache |
| 10 | Passkeys via go-webauthn: registration + assertion, counter and backup-state tracking, TOTP retained as fallback |
| 11 | Packaging: `Dockerfile.go-build`, compose, Unraid template, README, CI (build, vet, tests, DAV conformance, image smoke test) |

**Exit gate:** WebDAV mounts and round-trips files with real clients.

**Why grouped:** WebDAV is a second client of the same `vfs`, passkeys are a
second auth method, and packaging is the last mile. None of them changes the
user-facing product, so they can follow once phases 2–3 are proven and cutover
is imminent.

### Delivered

- **WebDAV** (`internal/dav`) — app passwords always work, the account password
  only when 2FA is off, so DAV is never a second-factor bypass. The auth cache
  is bounded so an unauthenticated client cannot grow it. `LOCK` is
  advisory-only: a real lock table would let one client block another
  indefinitely after a crash, and these are the same user's files.
- **Passkeys** (`internal/auth/passkey.go`) — credential IDs and public keys
  sealed under the passkeys subkey. The RP ID and origin derive from the
  request, because the server runs on a LAN address, a hostname, or behind a
  proxy. In-flight ceremony state is sealed into a cookie, so a challenge can
  neither be forged nor replayed.
- **Housekeeping** — hourly trash retention, expired-session purge, and stale
  upload-part sweep. Without it, trash and `.part` files grow forever.
- **`cmd/verify-cutover`** — the strangler checklist as a runnable tool.

### Verified during this phase

- Full rclone round-trip: MKCOL, PUT, GET, COPY, DELETE, nested collections,
  size accounting, 404 on missing paths, 401 on bad credentials, traversal
  refused.
- `scripts/dav-conformance.sh` drives rclone against a live server, runs in CI,
  and is idempotent so it can also be run by hand before cutover.
- `verify-cutover` against a Node-generated `/config`: every migrated share
  link still resolves, setup is closed, trash sidecars match their data files.

---

## Strangler rollout (phase 4, still to do)

Run the Go server against the **same** `/config` and `/data` as Node, on a
different port, read-only on `/config` to avoid two writers migrating at once.

Verify before cutover — all of this is automated in `cmd/verify-cutover`:

- File listings and byte counts match at several depths
- Existing share links still resolve and download
- TOTP logins work (proves re-sealing round-tripped)
- Trash contents are intact and every item has its sidecar
- Zip download of a folder matches

Then: stop Node, start Go, `docker restart`, expect one re-login.

Keep the `.migrated.bak` files. Rollback to Node is a `mv` away until you are
satisfied.

Two manual checks the tool cannot make, because they need a password:

- Sign in as a user with 2FA enrolled and enter a live code from their
  authenticator app. This is the check that decides whether real users are
  locked out.
- Mount in Finder and Windows Explorer and drag a file both ways.

---

## Cross-phase rules

These hold in every phase — they are not stage-gated:

1. Every mutation is a real form POST with a real session check.
2. All user-data I/O goes through `vfs.Resolve`. Grep the tree for `os.Open`,
   `os.Create`, `filepath.Join(...DATA_DIR` — every hit is inside `internal/vfs`
   or `internal/upload`.
3. Every page works with JavaScript disabled.
4. No table, index, or cache holds a file's path, size, or metadata.

## Dependencies at a glance

```
Phase 1  ──►  Phase 2  ──►  Phase 3  ──►  Phase 4  ──►  cutover
 store         auth          htmx UI        WebDAV       (strangler
 migration     securepath    media          passkeys      rollout)
               upload        shares         packaging
```

Steps inside a phase are still ordered 1 → 11; nothing runs in parallel. The
phases exist to mark the four points where we can legitimately stop and
re-assess, not to license concurrent work.