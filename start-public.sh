#!/usr/bin/env sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

HOST=0.0.0.0 PORT=8088 exec "$ROOT/start.sh"
