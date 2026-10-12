#!/usr/bin/env bash
# WebDAV conformance round-trip against a running server.
#
# The plan names hand-rolled WebDAV edge cases as a risk and says to test
# against real clients rather than only unit tests. This drives rclone, which
# is what users actually mount with.
#
# Requires: the server running with a known admin password, and an app
# password. Expects to be run from the repository root.
set -euo pipefail

BASE="${MYCLOUD_BASE:-http://127.0.0.1:8686}"
USER="${MYCLOUD_USER:-ci}"
PASS="${MYCLOUD_PASS:-ci-password-123}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok()   { echo "  ok: $*"; }

echo "WebDAV conformance against $BASE"

if ! command -v rclone >/dev/null; then
  echo "SKIP: rclone not installed" >&2
  exit 0
fi

# --- obtain a session ------------------------------------------------------
# The script must be idempotent: CI may run it against a server that already
# has the account. There are three possible starting states.
COOKIES="$WORK/cookies"

# page_token fetches a page and extracts its CSRF token, following redirects so
# an authenticated session still yields a page.
page_token() {
  curl -sL -b "$COOKIES" -c "$COOKIES" "$BASE/$1" \
    | grep -o 'name="csrf_token" value="[^"]*"' | head -1 \
    | sed 's/.*value="//;s/"//'
}

if [ -z "$(page_token files)" ]; then
  # Not signed in. On a fresh install /login offers the setup form.
  setup_csrf=$(page_token login)
  if [ -n "$setup_csrf" ]; then
    curl -s -b "$COOKIES" -c "$COOKIES" -o /dev/null -X POST "$BASE/setup" \
      --data-urlencode "csrf_token=$setup_csrf" \
      --data-urlencode "username=$USER" \
      --data-urlencode "password=$PASS" || true
  fi
fi

if [ -z "$(page_token files)" ]; then
  # Still not signed in: log in. The login page carries the pre-session CSRF
  # token, which is distinct from the session token.
  login_csrf=$(page_token login)
  if [ -n "$login_csrf" ]; then
    curl -s -b "$COOKIES" -c "$COOKIES" -o /dev/null -X POST "$BASE/login" \
      --data-urlencode "csrf_token=$login_csrf" \
      --data-urlencode "username=$USER" \
      --data-urlencode "password=$PASS" || true
  fi
fi

csrf=$(page_token files)
if [ -z "$csrf" ]; then
  echo "SKIP: could not sign in as $USER; not running the DAV checks" >&2
  exit 0
fi

app_pw=$(curl -s -b "$COOKIES" -X POST "$BASE/api/auth/apppw" \
  -H "X-CSRF-Token: $csrf" -d "label=ci" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
[ -n "$app_pw" ] || fail "could not mint an app password"

# --- configure rclone --------------------------------------------------------
CONF="$WORK/rclone.conf"
cat > "$CONF" <<EOF
[dav]
type = webdav
url = $BASE/dav
vendor = other
user = $USER
pass = $(rclone obscure "$app_pw")
EOF
export RCLONE_CONFIG="$CONF"

r() { rclone "$@"; }

# rclone's plain ls shows files only; --dirs-only shows collections.
echo "1. authenticate and list"
r ls dav: >/dev/null || fail "rclone could not list the DAV root"

echo "2. MKCOL"
r mkdir dav:conformance || fail "MKCOL failed"
r lsf dav: --dirs-only | grep -q conformance || fail "collection not listed after MKCOL"

echo "3. PUT"
echo "webdav conformance payload" > "$WORK/file.txt"
r copy "$WORK/file.txt" dav:conformance/ || fail "PUT failed"
r lsf dav:conformance | grep -q file.txt || fail "uploaded file not listed"

echo "4. GET round-trip"
got=$(r cat dav:conformance/file.txt) || fail "GET failed"
[ "$got" = "webdav conformance payload" ] || fail "content mismatch: $got"

# copyto/deletefile are used rather than copy/delete: with a WebDAV backend,
# `copy src dst-without-slash` makes rclone MKCOL the destination, so the file
# ends up as a collection. copyto names the destination explicitly.
echo "5. COPY within the collection"
r copyto dav:conformance/file.txt dav:conformance/copy.txt || fail "COPY failed"
r lsf dav:conformance | grep -q copy.txt || fail "copied file not listed"

echo "6. nested collections"
r mkdir dav:a/b/c || fail "nested MKCOL failed"
r lsf dav:a --dirs-only | grep -q b || fail "nested collection not listed"

echo "7. DELETE"
r deletefile dav:conformance/copy.txt || fail "DELETE failed"
if r lsf dav:conformance | grep -q copy.txt; then fail "deleted file still listed"; fi
ok "deleted file is gone"

echo "8. size accounting"
r size dav:conformance | grep -q "Total objects" || fail "size failed"

echo "9. missing paths answer 404, not 500"
code=$(curl -s -o /dev/null -w '%{http_code}' -u "$USER:$app_pw" \
  -X PROPFIND -H 'Depth: 0' "$BASE/dav/definitely-not-here")
[ "$code" = "404" ] || fail "PROPFIND on a missing path returned $code, want 404"
ok "missing path returns 404"

echo "10. bad credentials answer 401"
code=$(curl -s -o /dev/null -w '%{http_code}' -u "$USER:wrong" \
  -X PROPFIND "$BASE/dav/")
[ "$code" = "401" ] || fail "bad credentials returned $code, want 401"
ok "bad credentials rejected"

echo "11. traversal cannot escape the root"
code=$(curl -s -u "$USER:$app_pw" "$BASE/dav/../../../etc/passwd" -o /dev/null -w '%{http_code}')
[ "$code" != "200" ] || fail "traversal returned 200"
ok "traversal refused"

echo
echo "WebDAV conformance: all checks passed"