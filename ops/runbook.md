# OPS-01 Runbook — reference deployment operations

Scope: the packaged reference stack (`deploy/reference/`, compose project
`oaa-ref`, 6 Langfuse services + evidence-index stub on 127.0.0.1). Default
ports 3301/3302/18123/19000; the OPS-01 install ran on the shifted ports
**3401 / 3402 / 18124 / 19001** because the OBS-01 spike stack holds the
defaults (see docs/spikes/OPS-01-findings.md). Substitute the live values
from the install `.env` wherever a port appears below.

Standing deployment gate: `LANGFUSE_MIGRATION_V4_WRITE_MODE=dual`
(`deploy/reference/docker-compose.yml`). Verified live after the fresh install:
`docker exec oaa-ref-langfuse-web-1 env | grep MIGRATION` →
`LANGFUSE_MIGRATION_V4_WRITE_MODE=dual` and the legacy read API returns the
proof trace (`GET /api/public/traces/<id>` → 200).

## 1. Prerequisites

- docker 29+ (`docker info`), openssl, ≥5 GB free disk.
- Free host ports: `OAA_WEB_PORT`, `OAA_EVIDENCE_PORT`, `OAA_CH_HTTP_PORT`,
  `OAA_CH_NATIVE_PORT` (defaults 3301/3302/18123/19001).

## 2. Fresh install

```bash
OAA_WEB_PORT=3401 OAA_EVIDENCE_PORT=3402 \
OAA_CH_HTTP_PORT=18124 OAA_CH_NATIVE_PORT=19001 \
  bash deploy/reference/install.sh <install-dir>
```

install.sh: checks docker/openssl/ports/disk → generates `.env` (random
secrets + `LANGFUSE_INIT_*` keys, chmod 600) → `docker compose up -d --wait`
→ healthchecks `GET /api/public/health` (Langfuse) and `GET /healthz`
(evidence-index) → prints URLs. Proven 2026-11-04 from zero (see findings §2).

Never commit `.env`, `obs.env` or any `*.pem`. The install `.env` stays in the
install dir (git-excluded by `ops/scratch/.gitignore` for scratch installs;
keep any other install dir outside the repo or git-ignored).

## 3. Restart / recovery

Observed behaviour (findings §3): `restart: always` did **not** auto-resurrect
SIGKILLed langfuse-web/langfuse-worker containers (they stayed `Exited (137)`).
The proven recovery is:

```bash
cd <install-dir> && export COMPOSE_PROJECT_NAME=oaa-ref   # or use `-p oaa-ref`
docker compose --env-file .env up -d --wait   # healthy in ~19 s in the proven run
curl -fsS http://127.0.0.1:<web-port>/api/public/health
```

Then re-verify one known trace id through the read API. Always pass
`-p oaa-ref`/`COMPOSE_PROJECT_NAME=oaa-ref` — compose run without the project
name in a fresh dir creates a duplicate stack (this bit a probe run; see
findings §3 note).

Graceful restart (keeps state): `docker compose -p oaa-ref --env-file .env stop`
then `up -d --wait`.

## 4. Backup

Stop writes (or `docker compose -p oaa-ref --env-file .env stop`) for a
consistent snapshot, then:

```bash
bash ops/backup.sh <install-dir> <out-dir>
# -> <out-dir>/backup-<ts>/{postgres,clickhouse_data,clickhouse_logs,minio,redis}.tgz
#    + receipts.jsonl (evidence-index store) + backup.sha256sums.txt (per-file)
#    + BACKUP.sha256sums.txt (checksum of the manifest itself)
```

`.tgz` files are `tar czf` of each named volume; manifests are relative-pathed
so `sha256sum -c` works from any backup location.

## 5. Restore (proven round-trip)

Restore goes into a **separate compose project** (`oaa-ref-restore`) so live
volumes are never overwritten:

```bash
# live stack must be down/same ports free
OAA_ENV_SRC=<install-dir>/.env \
  bash ops/restore.sh <repo>/ops <out-dir>/backup-<ts> /home/craigamcw/oaa-reference-restore --verify
```

restore.sh: verifies `BACKUP.sha256sums.txt` (+ per-volume with `--verify`),
copies the compose file + stub, installs `.env` from `OAA_ENV_SRC`, recreates
`oaa-ref-restore_*` volumes from the archives, copies + re-hashes
`receipts.jsonl`, then `docker compose -p oaa-ref-restore --env-file .env up -d --wait`.

Verify after restore (runbook §5.4 checklist):

1. `curl -fsS http://127.0.0.1:<web-port>/api/public/health` → `{"status":"OK", ...}`;
2. read a pre-backup trace: `GET /api/public/traces/<trace-id>` (Basic auth from `.env`) → 200 + matching id;
3. evidence-index: `sha256sum <install-dir>/store/receipts.jsonl` vs the backup manifest hash;
   `GET /receipts/<id>` via the stub returns the receipt bytes-equal.

Proven run (2026-11-04, findings §4): health OK, trace readback 200, receipts
hash `ea8997e7…51ef` matched, 1202 traces visible post-restore.

Tear the restore project down afterwards:
`docker compose -p oaa-ref-restore --env-file .env down -v` and rm the volumes.

## 6. Upgrade procedure (Langfuse / any service image)

1. **Version recheck checklist before bumping:**
   - [ ] read the upstream release notes for the new tag for breaking API/CLI changes;
   - [ ] **re-check the dual-mode gate**: confirm the new image still honours
         `LANGFUSE_MIGRATION_V4_WRITE_MODE=dual` and that the compose file still
         sets it explicitly (grep `LANGFUSE_MIGRATION_V4_WRITE_MODE` in
         `deploy/reference/docker-compose.yml` — must be `dual`);
   - [ ] **re-check the version pin**: every `image:` in
         `deploy/reference/docker-compose.yml` has an explicit tag (no `latest`);
         update all Langfuse images (`langfuse`, `langfuse-worker`) to the same new tag;
   - [ ] re-check compose schema/config validity: `docker compose -p oaa-ref -f
         deploy/reference/docker-compose.yml config >/dev/null`;
   - [ ] confirm the evidence read path works on the new version with a scratch
         install (§2) before touching the live one.
2. Backup first (§4).
3. Re-run install.sh (or edit the install dir's compose copy + `docker compose
   up -d --wait` and watch migrations).
4. Post-upgrade healthcheck + trace readback + receipt hash — same as §5.4.
5. If the read API 404s: check `LANGFUSE_MIGRATION_V4_WRITE_MODE` actually
   reached the container (`docker exec oaa-ref-langfuse-web-1 env | grep
   MIGRATION`) before anything else.

## 7. Secret handling

- Never commit `.env`, `obs.env`, `*.pem`, API keys `pk-lf-…`/`sk-lf-…`,
  NEXTAUTH_SECRET/SALT/ENCRYPTION_KEY or generated admin passwords.
- `ENCRYPTION_KEY`/`SALT` are unrecoverable — data becomes unreadable if lost;
  host backup of `.env` belongs outside the repo.
- Ops scratch outputs exclude envs by `ops/scratch/.gitignore`.
- Key rotation: regenerate in Langfuse UI; update `.env` consumer keys; re-run
  §5 verification for key-derived path (receipts are key-independent so they
  survive key rotation — only the read API auth changes).

## 8. Teardown

```bash
docker compose -p oaa-ref -f <install-dir>/docker-compose.yml --env-file <install-dir>/.env down -v
rm -rf <install-dir>/store        # unless receipts must be kept (archive first, §4)
```

The `-v` removes the named volumes (destructive — backup first). Keep the
`.env` only if you plan to restore this exact stack later.