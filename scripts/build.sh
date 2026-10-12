#!/usr/bin/env bash
# Build the my-cloud binary, stamping the version from the VERSION file.
#
# VERSION is the single source of truth. Everything else — the git tag, the
# container image tag, the /api/version response — derives from it, so the
# three cannot drift apart.
#
# Usage:
#   ./scripts/build.sh              # build ./my-cloud
#   ./scripts/build.sh --static     # also cross-compile a linux/amd64 build
#   ./scripts/build.sh --test       # run the tests instead of building
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION_FILE=VERSION
[[ -f $VERSION_FILE ]] || { echo "error: $VERSION_FILE not found" >&2; exit 1; }
VERSION=$(tr -d '[:space:]' < "$VERSION_FILE")

# Guard against a malformed version. Docker tags are unforgiving: a space or a
# slash silently produces a wrong tag or a broken publish, so it is checked
# here rather than discovered in the registry.
if [[ ! $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: VERSION must be X.Y.Z (semver), got '$VERSION'" >&2
  exit 1
fi

COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo none)
DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
PKG=github.com/derek/my-cloud/internal/version
LDFLAGS="-X $PKG.Version=$VERSION -X $PKG.Commit=$COMMIT -X $PKG.Date=$DATE"

echo "building my-cloud $VERSION (commit $COMMIT)"

run_tests() {
  echo "running tests..."
  go vet ./...
  go test ./... "$@"
}

case "${1:-}" in
  --test)
    shift
    run_tests "$@"
    ;;
  --static)
    CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS" -o my-cloud ./cmd/my-cloud
    echo "  ./my-cloud (host, $(go env GOOS)/$(go env GOARCH))"
    mkdir -p dist
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -ldflags "$LDFLAGS" -o dist/my-cloud-linux-amd64 ./cmd/my-cloud
    echo "  dist/my-cloud-linux-amd64"
    ;;
  *)
    # -trimpath keeps build paths out of the binary; -s -w drop the symbol
    # table and debug info.
    CGO_ENABLED=0 go build -trimpath -ldflags "$LDFLAGS -s -w" -o my-cloud ./cmd/my-cloud
    echo "  ./my-cloud"
    ./my-cloud --version
    ;;
esac

echo "done: $VERSION"