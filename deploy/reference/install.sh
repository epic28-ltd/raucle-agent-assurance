#!/usr/bin/env bash
# OPS-01 reference deployment — fresh-install script.
#
# Usage: install.sh [TARGET_DIR]
#   TARGET_DIR  directory to install into (default: /home/craigamcw/oaa-reference-stack).
#               Created if missing; the stack is run from there (compose project name
#               derived from the directory name) so the repo stays clean.
#
# What it does:
#   1. checks: docker present, required ports free (3301/3302/18123/19000 by default),
#      >=5 GB free disk, openssl available;
#   2. generates .env from env.template (random secrets + API keys) if missing;
#   3. copies the compose file + evidence_index stub + env template into the target;
#   4. docker compose up -d --wait;
#   5. post-install healthcheck (Langfuse /api/public/health + evidence-index /healthz);
#   6. prints URLs/ports and the API keys source (.env in the target dir).
#
# Exit codes: 0 ok, 1 preconditions failed, 2 compose/health failed.

set -euo pipefail

SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_DIR="${1:-/home/craigamcw/oaa-reference-stack}"
REF_DIR="$SELF_DIR"

log()  { echo "[install] $*"; }

# ---- 1. preconditions -------------------------------------------------------
command -v docker >/dev/null 2>&1 || { echo "FATAL: docker not found"; exit 1; }
docker info >/dev/null 2>&1 || { echo "FATAL: docker daemon not reachable"; exit 1; }
command -v openssl >/dev/null 2>&1 || { echo "FATAL: openssl not found (needed for key generation)"; exit 1; }

MISSING_PORTS=""
FAIL=0

# Port plan — overridable via exported env (e.g. a conflicting stack on the defaults):
#   OAA_WEB_PORT, OAA_EVIDENCE_PORT, OAA_CH_HTTP_PORT, OAA_CH_NATIVE_PORT
export OAA_WEB_PORT="${OAA_WEB_PORT:-3301}"
export OAA_EVIDENCE_PORT="${OAA_EVIDENCE_PORT:-3302}"
export OAA_CH_HTTP_PORT="${OAA_CH_HTTP_PORT:-18123}"
export OAA_CH_NATIVE_PORT="${OAA_CH_NATIVE_PORT:-19000}"

FREE_DISK_GB="$(df --output=avail -BG / | awk 'NR==2 {gsub("G","",$1); print $1}')"
if [ "${FREE_DISK_GB:-0}" -lt 5 ]; then
  echo "FATAL: only ${FREE_DISK_GB}G free disk (need >=5G for Langfuse volumes)"
  FAIL=1
fi

port_in_use() {
  python3 - "$1" <<'PY'
import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(0)  # in use
sys.exit(1)
PY
}

for p in "$OAA_WEB_PORT" "$OAA_EVIDENCE_PORT" "$OAA_CH_HTTP_PORT" "$OAA_CH_NATIVE_PORT"; do
  if port_in_use "$p"; then
    echo "FATAL: port $p already in use on 127.0.0.1 (stop the conflicting stack, e.g. the OBS-01 spike compose) or shift the OAA_*_PORT overrides, e.g. OAA_WEB_PORT=3401 OAA_EVIDENCE_PORT=3402 OAA_CH_HTTP_PORT=18124 OAA_CH_NATIVE_PORT=19001"
    MISSING_PORTS="$MISSING_PORTS $p"
    FAIL=1
  fi
done
[ "$FAIL" = 0 ] || exit 1
log "preconditions ok (docker up, openssl ok, ports free, ${FREE_DISK_GB}G disk free)"
log "ports: web=${OAA_WEB_PORT} evidence=${OAA_EVIDENCE_PORT} ch_http=${OAA_CH_HTTP_PORT} ch_native=${OAA_CH_NATIVE_PORT}"

# ---- 2. target dir + .env ---------------------------------------------------
mkdir -p "$TARGET_DIR"
cd "$TARGET_DIR"
cp "$REF_DIR/docker-compose.yml" docker-compose.yml
mkdir -p evidence_index store
cp "$REF_DIR/evidence_index/stub.py" evidence_index/stub.py

if [ ! -f .env ]; then
  hex64() { openssl rand -hex 32; }
  hex24() { openssl rand -hex 12; }
  pk() { echo "pk-lf-$(openssl rand -hex 16)"; }
  sk() { echo "sk-lf-$(openssl rand -hex 16)"; }
  ADMIN_PASS="$(openssl rand -hex 12)"
  PK="$(pk)"; SK="$(sk)"
  log "generating .env with random secrets in $TARGET_DIR/.env"
  cat > .env <<EOF
OAA_WEB_PORT=${OAA_WEB_PORT}
OAA_EVIDENCE_PORT=${OAA_EVIDENCE_PORT}
OAA_CH_HTTP_PORT=${OAA_CH_HTTP_PORT}
OAA_CH_NATIVE_PORT=${OAA_CH_NATIVE_PORT}
NEXTAUTH_URL=http://127.0.0.1:${OAA_WEB_PORT}
NEXTAUTH_SECRET=$(hex64)
SALT=$(hex64)
ENCRYPTION_KEY=$(hex64)
REDIS_AUTH=$(hex24)
MINIO_ROOT_PASSWORD=$(hex24)
POSTGRES_PASSWORD=$(hex24)
CLICKHOUSE_PASSWORD=$(hex24)
LANGFUSE_INIT_ORG_ID=oaa-org
LANGFUSE_INIT_ORG_NAME=Open Agent Assurance
LANGFUSE_INIT_PROJECT_ID=oaa-project
LANGFUSE_INIT_PROJECT_NAME=oaa-reference-agent
LANGFUSE_INIT_PROJECT_PUBLIC_KEY=$PK
LANGFUSE_INIT_PROJECT_SECRET_KEY=$SK
LANGFUSE_INIT_USER_EMAIL=admin@example.invalid
LANGFUSE_INIT_USER_NAME=admin
LANGFUSE_INIT_USER_PASSWORD=$ADMIN_PASS
OAA_LF_URL=http://127.0.0.1:${OAA_WEB_PORT}
OAA_LF_PUBLIC_KEY=$PK
OAA_LF_SECRET_KEY=$SK
OAA_OTLP_ENDPOINT=http://127.0.0.1:${OAA_WEB_PORT}/api/public/otel/v1/traces
OAA_EVIDENCE_URL=http://127.0.0.1:${OAA_EVIDENCE_PORT}
EOF
  chmod 600 .env
else
  log ".env already present in $TARGET_DIR (kept as-is)"
fi

# normalise NEXTAUTH_URL to the configured web port
WEB_PORT="$(grep '^OAA_WEB_PORT=' .env | cut -d= -f2-)"
WEB_PORT="${WEB_PORT:-3301}"

# ---- 3. compose up --wait ---------------------------------------------------
# Fixed project name so volume names (oaa-ref_*) are predictable for backup/restore.
export COMPOSE_PROJECT_NAME=oaa-ref
log "docker compose up -d --wait (project: oaa-ref, from $TARGET_DIR)"
docker compose --env-file .env up -d --wait || { echo "FATAL: compose up --wait failed"; exit 2; }

# ---- 4. post-install healthcheck -------------------------------------------
lf_up() { curl -fsS "http://127.0.0.1:${WEB_PORT}/api/public/health" >/dev/null 2>&1; }
ev_up()  { curl -fsS "http://127.0.0.1:${OAA_EVIDENCE_PORT}/healthz" >/dev/null 2>&1; }
ok=0
for i in $(seq 1 30); do
  if lf_up && ev_up; then ok=1; break; fi
  sleep 2
done
if [ "$ok" != 1 ]; then
  echo "FATAL: post-install healthcheck failed (langfuse api: $(lf_up && echo up || echo DOWN), evidence-index: $(ev_up && echo up || echo DOWN))"
  docker compose --env-file .env ps
  exit 2
fi

log "INSTALL OK — healthchecks green"
cat <<EOF

  Langfuse UI     : http://127.0.0.1:${WEB_PORT}   (login: values in .env LANGFUSE_INIT_USER_*)
  OTLP endpoint   : http://127.0.0.1:${WEB_PORT}/api/public/otel/v1/traces
  evidence-index  : http://127.0.0.1:${OAA_EVIDENCE_PORT}  (GET /healthz, POST /receipts, GET /receipts/<id>)
  ClickHouse      : http://127.0.0.1:${OAA_CH_HTTP_PORT} (http), 127.0.0.1:${OAA_CH_NATIVE_PORT} (native)
  API keys + URLs : $TARGET_DIR/.env (LANGFUSE_INIT_PROJECT_PUBLIC_KEY / _SECRET_KEY; chmod 600)
  volumes         : oaa-ref_langfuse_{postgres,clickhouse_data,clickhouse_logs,minio,redis}_data
                    + ./store (evidence-index receipts)
  runbook         : ops/runbook.md (backup/restore/restart/upgrade/teardown)
EOF