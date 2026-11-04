# deploy/reference — OPS-01 packaged reference deployment

The shipped reference companion stack for Raucle Agent Assurance: Langfuse v4.74.0
self-hosted (6 services) + a volume-backed evidence-index stub (7th service).

## Install (fresh)

```bash
bash deploy/reference/install.sh <target-dir>   # default /home/craigamcw/oaa-reference-stack
```

The script checks docker/ports(3301, 3302, 18123, 19000)/disk, generates `.env`
(random secrets + `LANGFUSE_INIT_*` API keys, chmod 600) from `env.template`,
runs `docker compose up -d --wait` under compose project `oaa-ref`, healthchecks
Langfuse `/api/public/health` + evidence-index `/healthz`, then prints URLs.

> **DEPLOYMENT GATE — do not "fix" this away:** `LANGFUSE_MIGRATION_V4_WRITE_MODE`
> is pinned to **`dual`** in `docker-compose.yml` (both the shared anchor and
> nothing else). v4.74.0 self-host defaults to `events_only`, which 404s the legacy
> read API the evidence plane depends on (ADR-0003). Every upgrade re-checks this
> gate: ops/runbook.md §6.5.

## Ports (all bound to 127.0.0.1)

| Port  | Service                        |
|-------|--------------------------------|
| 3301  | langfuse-web (UI + OTLP + API) |
| 3302  | evidence-index stub            |
| 18123 | ClickHouse http (debug)        |
| 19000 | ClickHouse native (debug)      |

## OTLP: direct vs collector

The reference path is **direct OTLP** from the agent to
`http://127.0.0.1:3301/api/public/otel/v1/traces` (Basic auth with the
`pk-lf-`/`sk-lf-` keys from `.env`) — validated in OBS-01, recorded in ADR-0003.
No otel-collector ships in this stack; that keeps the reference minimal. If you
need the redaction processor (packages/instrumentation), run a collector
separately with an OTLP HTTP receiver on 4318 and point `OAA_OTLP_ENDPOINT` at
it (`<collector>:4318`); Langfuse still receives via its OTLP endpoint — no
change to this compose file. Both options are equivalent from Langfuse's view;
direct OTLP is what the runbook and the load smoke exercise.

## evidence-index stub

`evidence_index/stub.py` is a stdlib-only append-only receipt store on
`./store/receipts.jsonl` (bind mount — survives container rebuild; backed up and
hash-checked by ops/backup.sh). API: `GET /healthz`, `POST /receipts`,
`GET /receipts/<id>`, `GET /receipts`. It proves the receipt read path across
backup/restore; the planned evidence-index service replaces it
(services/evidence-index/README.md) and migrates the same store format.

## Volumes / state

- Docker named volumes `oaa-ref_langfuse_{postgres,clickhouse_data,clickhouse_logs,minio,redis}_data`.
- Bind mounts: `./store` (evidence-index receipts).
- Secrets: `.env` in the install dir only (chmod 600, git-ignored by the caller).
  `env.template` carries placeholders only.

See ops/runbook.md for backup/restore (proven round-trip), restart/recovery,
upgrade checklist, teardown.