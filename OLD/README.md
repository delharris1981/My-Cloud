# OLD — the archived Node implementation

This is the original Node/Express server that My Cloud shipped for years. It is
**not built or published from this directory any more**; the Go rewrite in the
repository root replaces it.

It is kept for two reasons:

1. **Rollback.** Until the Go server has run in production long enough to be
   trusted, the Node image remains the way back. Both builds read the same
   `/config` and `/data` volumes, so reverting means pointing the container at a
   different tag — not restoring files.
2. **Reference.** The Go migration is verified against data this code actually
   writes. `dev-config-gen.js` in the repository root imports
   `OLD/server/totp.js` to produce a realistic legacy `/config`, so the
   migration test runs against genuine TOTP secrets and bcrypt hashes rather
   than fixtures this repository invented. That test fails if this code drifts.

## Building it

The context is this directory, not the repository root:

```sh
docker build -t my-cloud:node OLD/
```

Or with compose:

```sh
docker compose -f OLD/docker-compose.node.yml up -d
```

## What is here

| Path | What it is |
| --- | --- |
| `server/` | The Express application |
| `public/` | Frontend: `app.js`, stylesheet, PWA assets |
| `templates/` | Unraid template for the Node image |
| `package.json` | Node dependencies |
| `Dockerfile.node` | Image definition |
| `docker-compose.node.yml` | Compose file |
| `docker-entrypoint.sh` | PUID/PGID handling |
| `ca_profile.xml` | AdGuard Home CA bundle, bundled for convenience |

## Do not change this to make the Go tests pass

`OLD/` is a fixed historical record. If a test depends on it and the test is
wrong, fix the test.