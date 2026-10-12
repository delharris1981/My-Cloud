#!/usr/bin/env bash
# Fail if VERSION was not bumped for a change.
#
# The rule is: every commit that changes anything substantive bumps VERSION. A
# commit that only reformats, updates docs, or bumps the version itself does
# not have to.
#
# Rationale: the version is the contract for the container tag and the git tag.
# If it can drift from the code, a bug report saying "I'm on 2.0.0" stops
# identifying a build, and a rollout has no way to say what it shipped.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION_FILE=VERSION
if [ ! -f "$VERSION_FILE" ]; then
  echo "error: VERSION file not found" >&2
  exit 1
fi

VERSION=$(tr -d '[:space:]' < "$VERSION_FILE")
if ! [[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: VERSION must be X.Y.Z, got '$VERSION'" >&2
  exit 1
fi

# On the first run (no parent commit) there is nothing to compare against.
BASE=$(git rev-parse --verify HEAD^ 2>/dev/null) || {
  echo "no parent commit; nothing to compare"
  exit 0
}

# A committed change means something other than docs, the version file itself,
# or generated archives is different from the parent commit.
if git diff --quiet "$BASE" HEAD -- . \
    ':(exclude)VERSION' \
    ':(exclude)docs/**' \
    ':(exclude)*.md' \
    ':(exclude)OLD/**'; then
  echo "no substantive change since $BASE; version bump not required"
  exit 0
fi

if git diff --quiet "$BASE" HEAD -- "$VERSION_FILE"; then
  echo "::error::substantive change since $BASE but VERSION is unchanged ($VERSION)"
  echo "        bump VERSION (X.Y.Z) as part of this change"
  echo "        patch for fixes, minor for features, major for breaking changes"
  exit 1
fi

echo "VERSION $VERSION was bumped for the change since $BASE"