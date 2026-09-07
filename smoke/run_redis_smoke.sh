#!/usr/bin/env bash
# Launch an ephemeral Redis (no persistence), run the atomic replay smoke, stop it.
set -euo pipefail
PORT="${CVZTTE_REDIS_PORT:-6399}"
HERE="$(cd "$(dirname "$0")" && pwd)"

redis-server --port "$PORT" --save "" --appendonly no --daemonize no --loglevel warning &
RPID=$!
trap 'kill "$RPID" 2>/dev/null || true' EXIT

# wait for readiness
for _ in $(seq 1 50); do
  if redis-cli -p "$PORT" ping 2>/dev/null | grep -q PONG; then break; fi
  sleep 0.1
done

CVZTTE_REDIS_URL="redis://127.0.0.1:${PORT}/0" python "$HERE/redis_atomic_smoke.py"
