#!/bin/sh
# Entrypoint for the Go build. Mirrors docker-entrypoint.sh: chown the volumes
# to PUID/PGID, then exec the server.
set -e

PUID="${PUID:-99}"
PGID="${PGID:-100}"
umask "${UMASK:-022}"

mkdir -p /config /data

chown -R "$PUID:$PGID" /config 2>/dev/null || echo "my-cloud: warning: could not chown /config"

# /data can be very large; only chown it when the owner actually changes, or
# every container start would walk the whole share.
MARKER="/config/.ownership"
WANT="${PUID}:${PGID}"
if [ "$(cat "$MARKER" 2>/dev/null)" != "$WANT" ]; then
  echo "my-cloud: setting ownership of /data to ${WANT} (one-time; may take a moment on large shares)…"
  chown -R "$PUID:$PGID" /data 2>/dev/null || echo "my-cloud: warning: could not chown /data"
  echo "$WANT" > "$MARKER" 2>/dev/null || true
fi

# exec so the binary becomes PID 1 and receives SIGTERM directly, which is
# what lets graceful shutdown run. The Go binary also drops privileges itself,
# so a non-root USER directive would be redundant.
exec su-exec "${PUID}:${PGID}" /app/my-cloud