#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PID_FILE="$ROOT/data/server.pid"
STATE_FILE="$ROOT/data/server-state.json"

if [ ! -f "$PID_FILE" ]; then
    echo "SBOM Scan is not running (no PID file)."
    exit 0
fi

PID=$(cat "$PID_FILE")
if ! kill -0 "$PID" 2>/dev/null; then
    rm -f "$PID_FILE" "$STATE_FILE"
    echo "Removed stale PID file; the server was not running."
    exit 0
fi

COMMAND=$(ps -p "$PID" -o args=)
if ! printf '%s' "$COMMAND" | grep -q "uvicorn app.main:app"; then
    echo "PID $PID does not belong to this project's Uvicorn server. Refusing to stop it." >&2
    exit 1
fi
if [ -e "/proc/$PID/cwd" ] && [ "$(readlink "/proc/$PID/cwd")" != "$ROOT" ]; then
    echo "PID $PID is running from another directory. Refusing to stop it." >&2
    exit 1
fi

kill "$PID"
COUNT=0
while kill -0 "$PID" 2>/dev/null && [ "$COUNT" -lt 20 ]; do
    sleep 0.25
    COUNT=$((COUNT + 1))
done
if kill -0 "$PID" 2>/dev/null; then kill -9 "$PID"; fi

rm -f "$PID_FILE" "$STATE_FILE"
echo "SBOM Scan stopped (PID $PID)."
