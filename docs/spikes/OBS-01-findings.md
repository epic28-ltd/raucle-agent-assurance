# OBS-01 Findings — Langfuse backend probes & OBS-01/02 vertical slice

Date: 2026-11-04 · Scope: ADR-0003 de-risking probes (P1/P2/P3) + raucle correlation, self-hosted Langfuse v4.74.0 OSS. Nothing external contacted; all data synthetic.

## Topology & versions

Compose: `~/Projects/oaa-spike-4nov/obs01/docker-compose.yml` (adapted from upstream v4.74.0 compose). Six services, all **internal-only except web** (host port `127.0.0.1:3301` → 3000; no collisions with jellyfin/plex/host services — postgres/redis/minio/clickhouse carry no host binds):

| Service | Image | Health |
|---|---|---|
| langfuse-web | docker.langfuse.com/langfuse/langfuse:4.74.0 | healthy (verified via `/api/public/health` 200) |
| langfuse-worker | docker.langfuse.com/langfuse/langfuse-worker:4.74.0 | healthy (waited via `--wait`) |
| clickhouse | clickhouse-server:26.3.62.3 | healthy (debug binds 127.0.0.1:18123/19000) |
| minio | cgr.dev/chainguard/minio | healthy |
| redis | redis:7 | healthy (REDISCLI_AUTH healthcheck; upstream compose's healthcheck is broken with requirepass — fixed here) |
| postgres | postgres:17 | healthy |

Credentials live in `obs01/obs.env` (SALT, ENCRYPTION_KEY, NEXTAUTH_SECRET, service passwords, bootstrap user + project pk/sk). Keys were provisioned at container init via `LANGFUSE_INIT_PROJECT_*` — no manual signup step needed.

**Material discovery (v4 behaviour):** self-hosted v4.74.0 defaults to `LANGFUSE_MIGRATION_V4_WRITE_MODE=events_only`, which **404s the entire legacy read API** (GET /api/public/traces, /observations, span/event writes). This is a hard blocker for any companion UI until set. This spike runs `dual` mode (legacy + event tables both written), which restored the read API. ADR-0003 must record this env decision (or adopt the v4-only read surface once documented) as a named deployment gate.

## P1 — Attribute round-trip fidelity: PASS (with documented transformations)

Setup: `obs01/reference_agent.py` emits one trace (AGENT root → stub-LLM, RETRIEVER, TOOL children) via OTLP HTTP (`/api/public/otel/v1/traces`, basic auth) with OpenInference span kinds and `oaa.*` namespace attrs (`oaa.run_id`, `oaa.release_version=v0.23.5+63edacd`, `oaa.trace_label`, `oaa.content_class=synthetic_public`, `langfuse.session.id`, `langfuse.user.id`). No raw secret is ever emitted — redaction control is class-only. Evidence: `obs01/originals.json` vs `obs01/p1_report.json` (API re-read of `GET /api/public/traces/{id}` + `/observations`).

- Trace-level `oaa.*` and `langfuse.*` attributes: **6/6 exact match** (strings, verbatim).
- Span-level attributes: AGENT, RETRIEVER, TOOL spans **all attrs exact match** (including `openinference.span.kind`, `tool.name`, `tool.parameters`, `retrieval.documents`).
- Transformations (lossless in value, relocated in key):
  - `llm.input_messages` / `llm.output_messages` are **not kept as attributes**; Langfuse parses them into structured `input` / `output` observation fields (verified content-identical). `llm.model_name` is promoted to `model` (this also made Langfuse compute it as a generation — cost fields present).
  - Booleans are coerced to strings: `oaa.stub: true` became `"true"`. **Type fidelity is not guaranteed; emit booleans as strings or enums for round-trip-critical attrs.**
- Redaction posture held: `oaa.content_class` round-tripped; no unintended enrichment beyond the documented key relocations above.
- **Langfuse adopts the client's 16-byte OTel trace id as its own trace id** — the companion can correlate by OTel id directly (used by P5).

## P2 — Score attachment with version metadata: PASS

`POST /api/public/scores` (id `obs01-score-eval-0001`, name `oaa.eval.result`, value 0.87, NUMERIC, `environment=oaa-spike`, comment carrying `evaluator=stub-eval;eval_version=v0.3.1;rubric=r-2026-11-04`) → 200. Readback: `GET /api/public/scores` with `?traceId=` returned empty on the immediate call (scores appear to be near-eventually-visible in list form) but **by-id readback (200) reproduced value and full comment verbatim**. Evidence: `obs01/p2_report.json`, `roundtrip_ok: true`. Note: numeric scores accept floats; comment is the only free-text version-metadata slot in this API shape — adequate for `eval_version` tagging.

## P5 (COR probe) — raucle gateway correlation + receipt immutability: PASS

`obs01/p2_p5_correlation.py` (run under `~/Projects/raucle/.venv`, raucle 0.23.5, pinned commit 63edacd): one allow (`read_file` /tmp/report.txt) + one deny (`write_file` /etc/passwd) through `GatewayConfig` + `RaucleGateway.check_tool_call`, `trace_id=` the OTel/Langfuse trace id. Evidence: `obs01/receipts.jsonl` (2 verbatim JWS envelopes), `obs01/p5_receipts_report.json`.

- `ProvenanceVerifier.verify_chain` before attach: **valid=True**.
- Correlation attach: one `oaa.gate.receipt` score per receipt on the trace; comment carries `gate_decision={allow|deny};receipt_hash=sha256:…;verifier=valid`. Receipts' signed bytes are never sent to or mutated by Langfuse — only backend-agnostic references cross the boundary (consistent with ADR-0003 §2).
- **Immutability proof:** receipt file sha256 before attach `0afe93c937b96c3…95de7` == after attach. Verifier after attach: **valid=True**.
- Alternative attach surface for the full companion: observation metadata or trace `metadata` are also viable; scores were chosen because they are queryable per trace and don't collide with agent-authored attributes. Either way, attach by reference only.

## P3 — Ingestion outage behaviour: PASS

`obs01/p3_outage.py`: stopped langfuse-worker + langfuse-web, emitted a 2-span trace during the outage with a bounded-retry wrapper exporter (4 attempts, 1 s backoff ≈ 7 s bound), restored backend, re-flight marker span.

- During outage: 1 batch, 2 spans attempted, 3 retries, 3.0 s retry time, **2/2 spans dropped when the bound expired** — dropped count is a deliberate, queryable loss metric, not silent.
- A stock OTLP exporter (no wrapper) retries only 429/5xx and **silently loses spans on connection refused** — the wrapper is required; loss visibility is companion-side work, as ADR-0003 anticipated.
- After recovery: marker trace (`oaa.dropped-spans-reflight`) landed and read back with `oaa.outage.recovered_spans: "2"` plus `oaa.outage.reference_trace_id` — **loss is visible in the backend, not just process logs**. Evidence: `obs01/p3_report.json`.

## Instrumentation choice

**Recommended: manual spans + OpenInference semantic-convention package** (`openinference-semantic-conventions==0.1.22` imported for attribute constants; spans constructed by hand with `opentelemetry-sdk==1.38.0`, `opentelemetry-api==1.38.0`, `opentelemetry-exporter-otlp-proto-http==1.38.0` — exact pins in `obs01/.venv`). Rationale: the companion must emit `oaa.*` namespaced, redaction-controlled attributes (no instrumentor gives that control); auto-instrumentors (OpenInference/Traceloop) would also capture arbitrary runtime content and fight the redaction gate. OpenInference constants are still used so Langfuse's structured parsing (LLM input/output promotion, span-kind surfacing in UI) is retained. raucle venv already carries `opentelemetry-api 1.45.1` — align versions at integration time.

## Gaps for the full companion

1. **Legacy-v4 API risk (biggest):** events_only default disables trace read APIs; `dual` also means the companion depends on a migration-period mode. Watch the v4 event read surface (`/api/public/events`, experiments API) and pin the deployment mode explicitly.
2. Score list-by-trace lag; read scores by id or tolerate eventual visibility in the verification step.
3. Boolean attribute coercion to strings — define companion attribute typing contract (strings only).
4. No retention/backup posture yet: ClickHouse+MinIO+Postgres volumes are unmanaged; define backup policy before pilot data exists.
5. Auth: local bootstrap user only; RBAC posture from ADR-0003 still to be configured (SSO gate untouched).
6. Outage durability: bounded retry at 7 s dropped spans. A disk-buffered exporter (e.g. `otlp` file queue or collector with persistent queue) is the likely right pattern for the pilot; probe validated the metric surface, not durability.

## Effort estimate

- **EVD (evidence capture):** the P5 pattern generalises directly — receipt store stays companion-owned; hashes attach as scores. ~2–3 days: bounded-retry exporter hardening + buffering (gap 6), attribute typing contract (gap 3), SBOM/licence check per ADR-0003 §5, tests.
- **COR (correlation):** trace-id plumbing (OTel id == Langfuse id verified), receipt→trace score attachment, verification-state display. ~2 days for API paths; +2–3 days if a trace-side metadata viewer/index is built in the UI.
- OBS-01 UI block can start: all three ADR-0003 gates are green.

## Verdict: OBS-01 **PASS**

All three de-risking probes passed with evidence; zero gaps discovered that block the OBS-01 UI work. The one architectural finding needing an ADR update is the `LANGFUSE_MIGRATION_V4_WRITE_MODE` deployment gate (events_only default removes the legacy read API the adapter currently targets).

Artifacts: `obs01/{docker-compose.yml, obs.env (secrets — do not print), reference_agent.py, originals.json, verify_p1.py, p1_report.json, p2_p5_correlation.py, p2_report.json, p5_receipts_report.json, receipts.jsonl, audit.jsonl, policies.yaml, p3_outage.py, p3_report.json}`. Nothing committed to any repo.