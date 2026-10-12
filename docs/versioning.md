# Versioning

`VERSION` at the repository root is the single source of truth. Everything else
derives from it: the git tag, the container image tag, and the version the
running server reports.

## The rule

**Every change that alters behaviour bumps `VERSION` by one step:**

| Bump | When | Example |
| --- | --- | --- |
| **patch** `X.Y.Z+1` | Bug fix, security fix, performance work, internal refactor | Traversal payload now rejected |
| **minor** `X.Y.Z → X.Y+1.0` | New feature, new endpoint, new option | WebDAV support |
| **major** `X.Y.Z → X+1.0.0` | Breaking change: a removed option, a changed default, a format change | Node app archived, Go rewrite |

Changes that do **not** need a bump: documentation, comments, the `VERSION`
file itself, and anything confined to `OLD/` (the archived Node app is a frozen
historical record).

`scripts/check-version.sh` runs in CI and fails the build if a substantive
change landed without one. That is deliberate friction: the version is the
contract for "I am running 2.0.3", and if it can drift from the code, a bug
report stops identifying a build.

## Where the version shows up

```sh
$ cat VERSION
2.0.0

$ ./my-cloud --version
my-cloud 2.0.0 (commit 8d6ab8c, 2026-10-12T11:36:08Z, go1.27.2)

$ curl -s localhost:8686/api/version
{
  "version": "2.0.0",
  "commit": "8d6ab8c",
  ...
}
```

`/api/status` also carries the version, so a single health probe identifies the
build.

## Making a release

```sh
# 1. Set the version.
echo 2.1.0 > VERSION

# 2. Build and check it locally.
./scripts/build.sh
./scripts/build.sh --test

# 3. Commit and tag.
git commit -am "Release 2.1.0"
git tag -a v2.1.0 -m "Release 2.1.0"
git push origin main --tags
```

The Gitea workflow picks the tag up on the mirror and pushes the image to GHCR
with these tags:

| Tag | Moves? | Meaning |
| --- | --- | --- |
| `2.1.0` | never | The exact release |
| `2.1` | yes | Newest release in the 2.1 line |
| `2` | yes | Newest release in the 2.x line |
| `sha-abc1234` | never | That commit's build |
| `latest` | only on the highest version | What an unqualified pull gets |

`latest` deliberately does **not** follow every commit. It only moves when the
commit being built carries the highest version ever released, so merging an old
branch cannot drag every user back to an old image.