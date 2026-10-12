#!/usr/bin/env bash
# Check the accounts a Dockerfile creates against the base image's real
# passwd/group databases.
#
# This exists because of a real failure. The image build died at the runtime
# stage with:
#
#   process "/bin/sh -c addgroup -g 100 -S mycloud && adduser ..." exited 1
#
# Alpine already defines a "users" group at GID 100, which is exactly the PGID
# this image defaults to, so addgroup refused to create a second group at a GID
# that was already taken.
#
# Nothing local catches this. `go build` is unaffected, the Dockerfile reads
# fine on its own, and the collision only exists in the base image — which is
# downloaded, never vendored. So this downloads the base image's minirootfs,
# extracts the two databases, and checks the Dockerfile's adduser/addgroup
# calls against them.
set -euo pipefail

cd "$(dirname "$0")/.."

DOCKERFILE=${1:-Dockerfile.go-build}
[ -f "$DOCKERFILE" ] || { echo "error: $DOCKERFILE not found" >&2; exit 1; }

# The base image is built for the runner's architecture. CI builds linux/amd64;
# override for anything else.
ARCH=${ARCH_OVERRIDE:-$(uname -m)}
case "$ARCH" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) echo "warning: unrecognised arch '$ARCH', defaulting to x86_64" >&2; ARCH=x86_64 ;;
esac

# The last FROM is the runtime stage, which is the one that creates accounts
# and is the one that failed.
BASE=$(sed -nE 's/^[[:space:]]*FROM[[:space:]]+([^[:space:]]+).*/\1/p' "$DOCKERFILE" | tail -1)
[ -n "$BASE" ] || { echo "error: no FROM in $DOCKERFILE" >&2; exit 1; }

# Only alpine is handled. The archived Node image is debian-based; a caller can
# point at it explicitly, and anything else is reported rather than guessed at.
case "$BASE" in
  alpine:*)
    ALPINEREL=${BASE#alpine:}
    # alpine publishes per-series directories: v3.20 holds 3.20.x. The Dockerfile
    # may pin either the series or an exact patch, so drop the patch only when
    # one is present. Stripping unconditionally would turn 3.20 into v3.
    case "$ALPINEREL" in
      *.*.*) SERIES="v$(printf '%s' "$ALPINEREL" | cut -d. -f1,2)" ;;
      *)     SERIES="v$ALPINEREL" ;;
    esac
    ;;
  *)
    echo "skip: base image '$BASE' is not alpine; pass 1 to acknowledge"
    exit 0
    ;;
esac

echo "checking accounts against $BASE ($ARCH)"

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

DIRURL="https://dl-cdn.alpinelinux.org/alpine/$SERIES/releases/$ARCH"

# The patch version is not pinned in the Dockerfile, so take the newest
# minirootfs published for the series. The group layout only changes on a
# release, so any build of the series is representative.
TARBALL=$(curl -fsS --max-time 120 "$DIRURL/" \
  | grep -oE "alpine-minirootfs-${ALPINEREL}\.[0-9]+-${ARCH}\.tar\.gz" \
  | sort -V | tail -1) || true

if [ -z "$TARBALL" ]; then
  echo "  ✗ could not list $DIRURL — cannot verify accounts" >&2
  exit 1
fi

echo "  base image snapshot: $TARBALL"
curl -fsS --max-time 180 "$DIRURL/$TARBALL" -o "$ROOT/base.tar.gz"

# Extract the whole archive rather than naming the members. The archive stores
# its paths with a leading "./", and GNU tar — the one on the CI runner —
# refuses a bare member name against it:
#
#   tar: etc/passwd: Not found in archive
#   tar: Exiting with failure status due to previous errors   (exit 2)
#
# bsdtar, which is what macOS ships, tolerates the same request, so this passed
# locally and failed on the runner. Extracting everything sidesteps member
# matching altogether. It is safe without root: a minirootfs holds only files,
# directories and symlinks, with no device nodes to create.
"${TAR:-tar}" xzf "$ROOT/base.tar.gz" -C "$ROOT" --no-same-owner

PASSWD=$(find "$ROOT" -path '*/etc/passwd' -print -quit)
GROUP=$(find "$ROOT" -path '*/etc/group' -print -quit)

if [ -z "$PASSWD" ] || [ -z "$GROUP" ]; then
  echo "  ✗ no /etc/passwd and /etc/group in the base image snapshot" >&2
  echo "    looked under $ROOT; extracted with: ${TAR:-tar} --version" >&2
  exit 1
fi

# Report an account creation only when the Dockerfile actually makes one.
FAILFILE="$ROOT/fail"
: > "$FAILFILE"

# Groups this Dockerfile creates itself. A `-G` naming one of these is not
# missing: addgroup has already made it by the time adduser runs.
created_groups=$(
  grep -oE '\b(addgroup|groupadd)\b[^&|;]*' "$DOCKERFILE" \
  | sed -E 's/^(addgroup|groupadd)[[:space:]]+//' \
  | tr ' \t' '\n' \
  | grep -vE '^-' \
  | grep -vE '^[0-9]+$' \
  | grep -E '^[A-Za-z_]' \
  | sort -u \
  || true
)

adds=$(grep -E '^[[:space:]]*RUN[[:space:]].*\b(adduser|addgroup|useradd|groupadd)\b' "$DOCKERFILE" || true)
if [ -z "$adds" ]; then
  echo "  no adduser/addgroup/useradd/groupadd in $DOCKERFILE — nothing to check"
  exit 0
fi

echo "$adds" | while IFS= read -r line; do
  case "$line" in
    *addgroup*|*"groupadd "*)
      # A group being created at a GID the base image already uses.
      gid=$(printf '%s' "$line" | grep -oE '(-g|--gid[= ]?)[ =]?[0-9]+' \
            | grep -oE '[0-9]+' | head -1 || true)
      if [ -n "$gid" ]; then
        owner=$(awk -F: -v g="$gid" '$3==g {print $1}' "$GROUP")
        if [ -n "$owner" ]; then
          echo "  ✗ in: $(printf '%s' "$line" | sed 's/^[[:space:]]*//')"
          echo "      creates a group at GID $gid, but the base image already has '$owner' at that GID."
          echo "      addgroup exits 1 and the image build fails."
          echo "      Join the existing group with -G $owner instead."
          echo x >> "$FAILFILE"
        fi
      fi
      ;;
  esac
  case "$line" in
    *adduser*|*useradd*)
      uid=$(printf '%s' "$line" | grep -oE '(-u|--uid[= ]?)[ =]?[0-9]+' \
            | grep -oE '[0-9]+' | head -1 || true)
      if [ -n "$uid" ]; then
        owner=$(awk -F: -v u="$uid" '$3==u {print $1}' "$PASSWD")
        if [ -n "$owner" ]; then
          echo "  ✗ in: $(printf '%s' "$line" | sed 's/^[[:space:]]*//')"
          echo "      creates an account at UID $uid, but the base image already has '$owner' at that UID."
          echo "      adduser exits 1 and the image build fails."
          echo x >> "$FAILFILE"
        fi
      fi
      # A group referenced with -G must already exist.
      grp=$(printf '%s' "$line" | grep -oE '(-G|--ingroup[= ]?)[ =]?[A-Za-z_][A-Za-z0-9_-]*' \
            | grep -oE '[A-Za-z_][A-Za-z0-9_-]*$' | head -1 || true)
      if [ -n "$grp" ] && ! printf '%s\n' "$created_groups" | grep -qx "$grp"; then
        if ! awk -F: -v g="$grp" '$1==g {found=1} END {exit !found}' "$GROUP"; then
          echo "  ✗ in: $(printf '%s' "$line" | sed 's/^[[:space:]]*//')"
          echo "      puts the account in group '$grp', which the base image does not define."
          echo "      adduser exits 1 and the image build fails."
          echo x >> "$FAILFILE"
        fi
      fi
      ;;
  esac
done

if [ -s "$FAILFILE" ]; then
  echo
  echo "The Dockerfile creates accounts that the base image already occupies."
  echo "Docker fails here, at image build, with no useful context in the error."
  exit 1
fi

echo "  ✓ every account the Dockerfile creates is free in the base image"