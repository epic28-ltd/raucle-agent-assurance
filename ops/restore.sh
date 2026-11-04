#!/usr/bin/env bash
# OPS-01 — restore the oaa-ref stack from a backup produced by backup.sh.
# Usage: restore.sh <REPO_OPS_DIR> <BACKUP_DIR> <RESTORE_DIR> [--verify]
#   REPO_OPS_DIR  the ops/ dir of the repo (provides deploy/reference sources)
#   BACKUP_DIR    a backup-<ts> dir from backup.sh
#   RESTORE_DIR   install-style dir to restore into; volumes are created under the
#                 restore project (oaa-ref-restore) so the live stack's volumes are
#                 never touched. Ports default to the same 127.0.0.1 bindings —
#                 stop the live stack first if it holds the ports (runbook §5).
#   --verify      require checksum match on every archive before restoring.
# After restore: copies env from the backup's install dir if REPO_OPS_DIR lacks one is
# NOT done — you must have (or copy) the original .env; compose up -d --wait runs at
# the end. The evidence-index store returns to RESTORE_DIR/store/receipts.jsonl with
# its sha256 re-checked so receipt readability across the round-trip is proven.

set -euo pipefail
OPS_DIR="${1:?usage: restore.sh <repo ops dir> <BACKUP_DIR> <RESTORE_DIR> [--verify]}"
BACKUP="${2:?usage: restore.sh <repo ops dir> <BACKUP_DIR> <RESTORE_DIR> [--verify]}"
RESTORE_DIR="${3:?usage: restore.sh <repo ops dir> <BACKUP_DIR> <RESTORE_DIR> [--verify]}"
VERIFY="${4:-}"

BACKUP="$(cd "$BACKUP" && pwd)"
RESTORE_DIR="$(mkdir -p "$RESTORE_DIR" && cd "$RESTORE_DIR" && pwd)"
REF="$OPS_DIR/../deploy/reference"

# checksum gate on the manifest itself, then (optionally) per-volume
( cd "$BACKUP" && sha256sum -c --strict BACKUP.sha256sums.txt >/dev/null ) \
  || { echo "FATAL: backup manifest checksum mismatch"; exit 2; }
if [ "$VERIFY" = "--verify" ]; then
  ( cd "$BACKUP" && sha256sum -c --strict backup.sha256sums.txt ) \
    || { echo "FATAL: per-volume checksum mismatch"; exit 2; }
fi

mkdir -p "$RESTORE_DIR/store"
cp "$REF/docker-compose.yml" "$RESTORE_DIR/docker-compose.yml"
cp -r "$REF/evidence_index" "$RESTORE_DIR/evidence_index"

# .env: reuse the original install .env if RESTORE_DIR doesn't have one.
# The caller should have copied it (host-only, never into git); fail loudly if absent.
if [ ! -f "$RESTORE_DIR/.env" ]; then
  SRC_ENV="${OAA_ENV_SRC:-}"
  if [ -n "$SRC_ENV" ] && [ -f "$SRC_ENV" ]; then
    cp "$SRC_ENV" "$RESTORE_DIR/.env"; chmod 600 "$RESTORE_DIR/.env"
    echo "[restore] .env from $SRC_ENV"
  else
    echo "FATAL: no .env in $RESTORE_DIR — copy the original install .env (e.g. OAA_ENV_SRC=/path/to/.env restore.sh ...)"; exit 2
  fi
fi

# create restore-project volumes and untar each backup archive into it
restore_vol() {  # restore_vol <name> <dst volume full name>
  docker volume create "$2" >/dev/null
  docker run --rm -v "$BACKUP/$1.tgz":/backup.tgz:ro -v "$2":/dst busybox \
    sh -c "tar xzf /backup.tgz -C /dst"
}
restore_vol postgres        oaa-ref-restore_langfuse_postgres_data
restore_vol clickhouse_data oaa-ref-restore_langfuse_clickhouse_data
restore_vol clickhouse_logs oaa-ref-restore_langfuse_clickhouse_logs
restore_vol minio           oaa-ref-restore_langfuse_minio_data
restore_vol redis           oaa-ref-restore_langfuse_redis_data

# evidence-index store restore + hash re-check
if [ -f "$BACKUP/receipts.jsonl" ]; then
  cp "$BACKUP/receipts.jsonl" "$RESTORE_DIR/store/receipts.jsonl"
  want="$(grep '^[0-9a-f]*  receipts.jsonl$' "$BACKUP/backup.sha256sums.txt" | awk '{print $1}')"
  got="$(sha256sum "$RESTORE_DIR/store/receipts.jsonl" | awk '{print $1}')"
  [ -z "$want" ] || [ "$want" = "$got" ] || { echo "FATAL: receipts.jsonl hash mismatch after copy ($want != $got)"; exit 2; }
  echo "[restore] receipts.jsonl restored, sha256 $got"
fi

cd "$RESTORE_DIR"
export COMPOSE_PROJECT_NAME=oaa-ref-restore
docker compose --env-file .env up -d --wait
echo "RESTORE OK — project oaa-ref-restore in $RESTORE_DIR"
echo "Next: verify healthchecks + a trace + a receipt against the restored volumes (runbook §5.4), then tear down."