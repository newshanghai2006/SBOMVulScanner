#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DATA_DIR="$ROOT/data"
PID_FILE="$DATA_DIR/server.pid"
STATE_FILE="$DATA_DIR/server-state.json"
STDOUT_LOG="$DATA_DIR/server.out.log"
STDERR_LOG="$DATA_DIR/server.err.log"
HOST=${HOST:-127.0.0.1}
PORT=${PORT:-8088}
CHECK_HOST=$HOST
case "$CHECK_HOST" in
    0.0.0.0|::|"[::]") CHECK_HOST=127.0.0.1 ;;
esac

mkdir -p "$DATA_DIR"

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null && ps -p "$PID" -o args= | grep -q "uvicorn app.main:app"; then
        echo "SBOM Scan is already running (PID $PID)."
        echo "URL: http://$HOST:$PORT"
        exit 0
    fi
    rm -f "$PID_FILE" "$STATE_FILE"
fi

PYTHON="$ROOT/.venv/bin/python"
if [ ! -x "$PYTHON" ]; then
    echo "Project virtual environment not found: $PYTHON" >&2
    echo "Create it with: python3 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt" >&2
    exit 1
fi

if ! "$PYTHON" - "$HOST" "$PORT" <<'PY'
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
sock = socket.socket()
try:
    sock.bind((host, port))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
then
    echo "Port $PORT is already in use. Stop that service or run PORT=<port> ./start.sh." >&2
    exit 1
fi

cd "$ROOT"
nohup "$PYTHON" -m uvicorn app.main:app --host "$HOST" --port "$PORT" >"$STDOUT_LOG" 2>"$STDERR_LOG" &
PID=$!
printf '%s\n' "$PID" > "$PID_FILE"
printf '{"pid":%s,"host":"%s","port":%s}\n' "$PID" "$HOST" "$PORT" > "$STATE_FILE"

READY=0
COUNT=0
while [ "$COUNT" -lt 20 ]; do
    sleep 0.5
    if ! kill -0 "$PID" 2>/dev/null; then break; fi
    if "$PYTHON" - "$CHECK_HOST" "$PORT" <<'PY' 2>/dev/null
import json, sys, urllib.request
data = json.load(urllib.request.urlopen(f"http://{sys.argv[1]}:{sys.argv[2]}/api/health", timeout=2))
raise SystemExit(0 if data.get("status") == "ok" else 1)
PY
    then READY=1; break; fi
    COUNT=$((COUNT + 1))
done

if [ "$READY" -ne 1 ]; then
    kill "$PID" 2>/dev/null || true
    rm -f "$PID_FILE" "$STATE_FILE"
    echo "SBOM Scan failed to start. Check $STDERR_LOG" >&2
    exit 1
fi

echo "SBOM Scan started (PID $PID)."
echo "URL: http://$HOST:$PORT"
echo "Stop: ./stop.sh"
