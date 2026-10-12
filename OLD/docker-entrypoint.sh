#!/bin/sh
# Drop from root to an unprivileged user before running the app. Uses the
# Unraid-standard PUID/PGID/UMASK so files land with the operator's ownership
# instead of root:root. Defaults are Unraid's nobody:users (99:100).
set -e

PUID="${PUID:-99}"
PGID="${PGID:-100}"
umask "${UMASK:-022}"

mkdir -p /config /data

# /config is small (settings, users, shares, session key) — ALWAYS ensure the
# app user owns everything inside it. The top-level folder is often already
# 99:100 on Unraid while the files inside were created root-owned by an older
# image, so we can't skip based on the folder's owner alone.
chown -R "$PUID:$PGID" /config 2>/dev/null || echo "my-cloud: warning: could not chown /config"

# /data can be large — do the full recursive chown only on first run or when
# PUID/PGID changed (tracked in a marker), so normal restarts stay fast.
MARKER="/config/.ownership"
WANT="${PUID}:${PGID}"
if [ "$(cat "$MARKER" 2>/dev/null)" != "$WANT" ]; then
  echo "my-cloud: setting ownership of /data to ${WANT} (one-time; may take a moment on large shares)…"
  chown -R "$PUID:$PGID" /data 2>/dev/null || echo "my-cloud: warning: could not chown /data"
  echo "$WANT" > "$MARKER" 2>/dev/null || true
fi

# su-exec accepts a numeric uid:gid directly — no user account needed.
exec su-exec "${PUID}:${PGID}" node server/index.js
