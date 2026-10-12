# SQLite for user accounts — recommendation

> Written during plan-mode discussion. NOT a build plan for the Go rewrite.

## Question
Would it be sensible to add a SQLite DB for user accounts?

## Answer
Yes, but scoped to **credentials + shares only**, and made optional at build time.
Not as a file-metadata layer.

## What adding SQLite actually breaks

| Claim | Still true? |
|---|---|
| "No database" (no server/daemon/port/creds to babysit) | ✅ Yes — SQLite is one file, `cp` to back up |
| "Flat filesystem, no DB for files" | ✅ Yes — files never touch SQL |
| "Stdlib only, CGO-free static binary" | ❌ **No** — Go stdlib has no SQLite |

Cost of that last break:
- `modernc.org/sqlite` — pure Go, keeps `CGO_ENABLED=0`. Transpiled C, ~10MB binary, slow to compile. Pragmatic pick.
- `mattn/go-sqlite3` — cgo, faster, breaks static build.

Net: "stdlib only" stops being true. Two deps, ~10MB binary. That is the entire price.

## Why yes (the tipping point)

The rewrite already commits to **WebAuthn passkeys**. Passkey credentials are
per-user records with counters and backup-eligible state — the point where
"rewrite a JSON blob on every mutation" stops being tidy, and where in-memory
state that must serialize every write becomes future work you'd throw away.

Other wins:
- Transactions across users + sessions + app passwords + TOTP + passkeys.
- Share links: indexed lookup by token; access counters; expiry sweeps as a
  query rather than a full scan per request.
- Durable audit log (logins, failed attempts, share access) — painful as
  append-only JSONL you must rotate and prune.

What you do NOT get: per-file metadata. Files stay flat regardless; mtime/perm
metadata still needs xattrs or a sidecar table.

## Scope boundary

| Stays plain files | Moves to SQLite |
|---|---|
| User files `/data/users/*/files` | Accounts |
| Trash | Sessions |
| Thumbnail cache | App passwords |
| `settings.json` (hand-editable, keep readable) | TOTP seeds — **encrypted at rest** |
| | Passkey credentials — **encrypted at rest** |
| | Share links + counters |
| | Audit log |

## Security note
TOTP seeds and passkey credentials in SQLite must be encrypted at rest.
Today they are plaintext JSON — tolerable for TOTP seeds, meaningfully worse
once passkeys land. AES-256-GCM per record, key derived from the app secret.
Fixing this is free if done during the move.

## The honest counterargument
Per-user credential files (`/config/creds/<user>.json`) would get you through
passkeys on JSON while keeping the zero-dependency, tiny-binary story clean —
and that is genuinely fine at this scale. If "pure Go, small, no deps" matters
more than transactional integrity + audit log, that route is defensible.

## Impact on build order
Choosing SQLite moves it to **step 1**, which changes migration from
"read existing JSON" to: read JSON → write SQL once → first boot.