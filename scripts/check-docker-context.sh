#!/usr/bin/env bash
# Fail if the Dockerfile copies something the build context will not contain.
#
# This exists because of a real failure. The Dockerfile had
#   COPY scripts ./scripts
# while .dockerignore excluded `scripts`, and the build died with
#   failed to calculate checksum of ref ...: "/scripts": not found
#
# Docker reports that late and in terms that read like a cache problem. A local
# `go build` is unaffected, and neither file is wrong on its own — the
# contradiction is between them, so only a check that reads both finds it.
set -euo pipefail

cd "$(dirname "$0")/.."

# The Dockerfile path is relative to the repository root, but a COPY source is
# relative to the *build context*, which is not always the root: the archived
# Node image builds from OLD/. Pass the context explicitly.
DOCKERFILE_PATH=${1:-Dockerfile.go-build}
IGNORE_PATH=${2:-.dockerignore}
CONTEXT=${3:-.}

exec python3 - "$DOCKERFILE_PATH" "$IGNORE_PATH" "$CONTEXT" <<'PY'
import fnmatch, re, shlex, sys

import glob as globmod

dockerfile, ignorefile, context = sys.argv[1], sys.argv[2], sys.argv[3]

import os
_docker_text = open(dockerfile).read()
_ignore_text = open(ignorefile).read()
if os.path.isdir(context):
    os.chdir(context)

# --- read the Dockerfile, collecting context COPY sources -------------------

text = _docker_text
text = re.sub(r"\\\s*\n\s*", " ", text)   # join line continuations

sources = []
for line in text.splitlines():
    line = line.strip()
    if not line.upper().startswith("COPY "):
        continue
    parts = shlex.split(line[5:])
    flags = []
    while parts and parts[0].startswith("--"):
        flags.append(parts.pop(0))
    if any(f.startswith("--from") for f in flags):
        continue      # copied from an earlier stage, not the build context
    if not parts:
        continue
    sources.extend(parts[:-1])   # last word is the destination

if not sources:
    print(f"no context COPY sources found in {dockerfile}")
    sys.exit(0)

# --- read .dockerignore -----------------------------------------------------

patterns = []
for raw in _ignore_text.splitlines():
    pat = raw.strip()
    if not pat or pat.startswith("#"):
        continue
    patterns.append(pat)

def ignored(relpath):
    """Return the first pattern excluding relpath, or None.

    Docker's rules, to the depth this repository actually uses:
      - a pattern with no slash matches a path component at any depth
      - a pattern with a slash is anchored to the context root
      - a trailing slash means "directories only"
      - a leading slash is just anchoring
      - '!' would re-include; none are used here, and an unsupported
        negation is reported rather than silently ignored
    """
    parts = relpath.split("/")
    for pat in patterns:
        if pat.startswith("!"):
            raise SystemExit(f"error: {ignorefile} uses a negation ({pat}), "
                             "which this check does not implement")
        neg = pat
        anchored = "/" in neg.strip("/")
        neg = neg.strip("/")
        if not anchored:
            if any(fnmatch.fnmatch(c, neg) for c in parts):
                return pat
        else:
            if fnmatch.fnmatch(relpath, neg) or fnmatch.fnmatch(relpath, neg + "/*"):
                return pat
    return None

# --- compare the two --------------------------------------------------------

problems = []
for src in sources:
    rel = src[2:] if src.startswith("./") else src.lstrip("/")

    # Resolve to a concrete path when the source is a directory or a file.
    if os.path.isdir(rel):
        probe = rel + "/x"          # representative file inside the dir
    elif os.path.exists(rel):
        probe = rel
    else:
        if any(ch in rel for ch in "*?["):
            if not globmod.glob(rel):
                problems.append((src, f"glob '{rel}' matches nothing"))
            continue
        problems.append((src, f"'{rel}' does not exist in the build context"))
        continue

    pattern = ignored(probe) or ignored(rel)
    if pattern:
        problems.append((src, f"excluded from the context by {ignorefile} "
                              f"(pattern {pattern!r})"))

if problems:
    for src, why in problems:
        print(f"  COPY {src} — {why}")
    print()
    print("The Dockerfile copies a path the build context will not contain.")
    print("Docker fails late, as 'failed to calculate checksum', which reads")
    print("like a cache problem rather than a context problem.")
    sys.exit(1)

print(f"every COPY source is in the build context ({dockerfile})")
PY