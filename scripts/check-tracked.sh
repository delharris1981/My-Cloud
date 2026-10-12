#!/usr/bin/env bash
# Fail if any source file on disk is not tracked by git.
#
# This exists because of a real failure: .gitignore had an unanchored `config/`
# pattern, which matched internal/config/ at any depth. Those two files were
# never committed, the tree built and passed every test locally, and the build
# only failed in CI with "no required module provides package
# github.com/derek/my-cloud/internal/config". Everything about the failure was
# invisible from the working copy — the files were right there.
#
# Untracked source is invisible to review and to `git push`, so it is worth an
# explicit check even though `go build` also catches it.
set -euo pipefail

cd "$(dirname "$0")/.."

# Files git would stage but has not been asked to: present on disk, not ignored,
# not tracked. This is exactly the set that silently disappears on a fresh
# checkout.
missing=$(git ls-files --others --exclude-standard -- \
  '*.go' '*.html' '*.css' '*.js' '*.xml' '*.yml' '*.yaml' '*.sh' 2>/dev/null || true)

if [ -n "$missing" ]; then
  echo "error: source files exist on disk but are not tracked by git:" >&2
  echo "$missing" | sed 's/^/  /' >&2
  {
    echo
    echo "A fresh checkout would not have them, so CI fails with"
    echo "'no required module provides package ...'. Either 'git add' them or"
    echo "fix the pattern excluding them — check .gitignore for an unanchored"
    echo "directory pattern such as 'config/', which matches at any depth."
  } >&2
  exit 1
fi

echo "every source file is tracked"