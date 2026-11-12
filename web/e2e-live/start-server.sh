#!/usr/bin/env bash
# Starts the real Citadel server for the live end-to-end suite (run by
# Playwright's webServer, see playwright.config.ts):
#
#   1. builds the console and embeds it (scripts/build-web.sh),
#   2. builds the server binary,
#   3. starts a fresh PostgreSQL in Docker on port 55508 (CITADEL_LIVE_PG_PORT), unless
#      CITADEL_LIVE_DB_URL points at one already (CI uses a service container),
#   4. runs the server in the foreground against it.
#
# Every run starts from an empty database, so the suite always exercises the
# first-run bootstrap. Set CITADEL_LIVE_SKIP_BUILD=1 to reuse the last build.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RUN_DIR="$ROOT/web/e2e-live/.run"
PORT="${CITADEL_LIVE_PORT:-18508}"
PG_PORT="${CITADEL_LIVE_PG_PORT:-55508}"
PG_CONTAINER="citadel-e2e-live-pg-$PG_PORT"
PG_PASSWORD=citadel-live-e2e-pw
mkdir -p "$RUN_DIR"
cd "$ROOT"

if [ "${CITADEL_LIVE_SKIP_BUILD:-}" != "1" ]; then
  ./scripts/build-web.sh
  GOFIPS140=latest go build -o "$RUN_DIR/citadel" ./cmd/server
fi

DB_URL="${CITADEL_LIVE_DB_URL:-}"
if [ -z "$DB_URL" ]; then
  docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
  docker run -d --rm --name "$PG_CONTAINER" -e POSTGRES_PASSWORD="$PG_PASSWORD" \
    -p "127.0.0.1:$PG_PORT:5432" postgres:17 >/dev/null
  trap 'docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true' EXIT
  for _ in $(seq 1 60); do
    if docker exec "$PG_CONTAINER" pg_isready -U postgres >/dev/null 2>&1; then break; fi
    sleep 1
  done
  # pg_isready can pass while the init scripts restart the server once.
  sleep 2
  DB_URL="postgres://postgres:$PG_PASSWORD@127.0.0.1:$PG_PORT/postgres?sslmode=disable"
fi

export KMS_DB_URL="$DB_URL"
export KMS_LISTEN_ADDR="127.0.0.1:$PORT"
export KMS_PUBLIC_URL="http://127.0.0.1:$PORT"
export KMS_UI_SECURE_COOKIES=false
export KMS_BOOTSTRAP_TOKEN="${CITADEL_LIVE_BOOTSTRAP_TOKEN:-live-e2e-bootstrap-token-0123456789}"
export KMS_WRAPPING_KEY_B64="$(openssl rand -base64 32)"
export KMS_ACCESS_KEY_ID=AKIALIVEE2E000000001
export KMS_SECRET_ACCESS_KEY=liveE2EsecretAccessKey0123456789abcdefghij
export KMS_LOG_FORMAT=text
export GODEBUG=fips140=only

# Not exec: the trap above must run to remove the database container.
"$RUN_DIR/citadel" &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; wait "$SERVER_PID" 2>/dev/null || true; docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true' EXIT INT TERM
wait "$SERVER_PID"
