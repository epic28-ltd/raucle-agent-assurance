#!/usr/bin/env bash
# OPS-01 — backup the oaa-ref stack volumes + evidence-index store.
# Usage: backup.sh <INSTALL_DIR> <OUT_DIR>
#   INSTALL_DIR  install dir containing the stack (default /home/craigamcw/oaa-reference-stack)
#   OUT_DIR      where the backup lands: OUT_DIR/backup-<ts>/ with one .tgz per volume
#                plus backup.sha256sums.txt and receipts.jsonl (evidence-index store).
# Volumes backed up: the 5 langfuse_* volumes of the oaa-ref compose project
# + the bound-mounted evidence-index store (INSTALL_DIR/store/receipts.jsonl).
# Never restore into the live stack directly — use restore.sh (runbook §5). The stack
# should be stopped (or writes paused) for a consistent backup: see runbook §4.

set -euo pipefail
INSTALL_DIR="${1:?usage: backup.sh <INSTALL_DIR> <OUT_DIR>}"
OUT_DIR="${2:?usage: backup.sh <INSTALL_DIR> <OUT_DIR>}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="$OUT_DIR/backup-$TS"
mkdir -p "$BACKUP"

volbackup() {  # volbackup <volume> <name>
  docker run --rm -v "$1":/src:ro busybox tar czf - -C /src . > "$BACKUP/$2.tgz"
}

volbackup oaa-ref_langfuse_postgres_data        postgres
volbackup oaa-ref_langfuse_clickhouse_data      clickhouse_data
volbackup oaa-ref_langfuse_clickhouse_logs      clickhouse_logs
volbackup oaa-ref_langfuse_minio_data           minio
volbackup oaa-ref_langfuse_redis_data           redis

if [ -f "$INSTALL_DIR/store/receipts.jsonl" ]; then
  cp "$INSTALL_DIR/store/receipts.jsonl" "$BACKUP/receipts.jsonl"
fi

( cd "$BACKUP" && sha256sum postgres.tgz clickhouse_data.tgz clickhouse_logs.tgz \
    minio.tgz redis.tgz *[r]eceipts.jsonl 2>/dev/null > backup.sha256sums.txt )
( cd "$BACKUP" && sha256sum backup.sha256sums.txt > BACKUP.sha256sums.txt )

echo "BACKUP OK -> $BACKUP"
cat "$BACKUP/BACKUP.sha256sums.txt"