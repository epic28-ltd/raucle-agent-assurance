# EXP-01 findings — generic SIEM webhook exporter

Status: PASS (transport + envelope + dead-letter, all offline-tested)
Date: 2026-11-04
Code: `integrations/siem/webhook.py` (stdlib-only core; PyYAML only for the
optional config loader, mirroring `services/rules`), config
`integrations/siem/config/webhook.yaml` + schema
`integrations/siem/config/webhook-config.schema.json`,
tests `tests/integrations-siem/test_webhook.py` (in-process dummy HTTP
server, no internet).

## Design

- **Envelope v1** (`envelope_version: "1"`): `event_id`, `event_time`
  (RFC3339 UTC, microseconds, `Z`), `kind` (`finding | verification |
  correlation | evidence_summary`), `org_id`, `agent_id`, `run_ref`,
  `trace_ref`, `receipt_hash`, `fields` per kind. Finding fields mirror the
  RULE-01 `Finding` model (`rule_id`, `rule_version`, `severity`,
  `confidence`, `evidence_refs`, `subject`,
  `redacted explanation`, `suppression_reason`) — index-plane only.
- **Stable identity**: `event_id` is UUIDv5 over the canonical JSON
  (sorted keys, tight separators) of every envelope input. Two runs
  building the same event produce the same envelope byte-for-byte — the
  receiver's dedup key survives exporter restarts and replay.
- **No secrets / raw content / payloads**: the builder fail-closes on any
  payload-bearing key name (payload, content, raw, jws, secret, token,
  credential, api_key, authorization, env, …). Finding explanations pass a
  table-driven redaction pass (RULE-01 SEC-008 style patterns:
  AWS access keys, bearer tokens, PEM keys, `secret=` key-value forms, long
  hex) and may carry **named placeholders only** (`<redacted:aws_access_key>`).
- **Transport**: stdlib `urllib` POST JSON; TLS/URL from env/config only
  (`OAA_SIEM_WEBHOOK_URL` overrides the file; `https` required unless
  `allow_http` opt-in for localhost fixtures). Bounded retry
  (`max_attempts`, exponential backoff `backoff_base_seconds * 2^n`) for
  5xx/429/network errors; 4xx dead-letters immediately (non-retryable).
- **Exhaustion → dead-letter JSONL file sink** (envelope + error + attempts
  + timestamp). Dead-lettered events are NOT marked sent — a later exporter
  run replays them (verified in tests).
- **At-least-once transport, envelope dedup**: sent `event_id`s persist to a
  small FIFO-capped JSON state file (`DedupStore`), so restarts do not
  re-send confirmed events. Transport retries re-deliver the identical
  envelope; the receiver merges **idempotently by `event_id`**
  (`IdempotentCollector` is the reference in-process merge — tested over a
  retry storm plus a late duplicate: N deliveries → 1 stored event).
- All network paths tested against a local dummy `http.server` inside
  pytest: retry-then-success (3 attempts), exhaustion → dead-letter,
  4xx non-retry, dedup persistence across exporter instances, receiver
  idempotent merge.

## Guarantees

- Deterministic `event_id` — same event never becomes two events.
- Envelope contents are closed-world: no canonical receipt bytes, no raw
  telemetry, no secret-shaped material (fixture secrets asserted absent).
- No data loss on exhaustion: dead-letter file retains the full envelope for
  replay.
- Exactly-once is NOT claimed anywhere: transport is at-least-once and
  safety rests on receiver-side `event_id` dedup (standard SIEM practice).

## Limits

- Retry is bounded and in-process; it does not survive exporter process
  death (dead-letter file is the durability story, replay is manual).
- Dedup state is FIFO-capped (default 10k): events older than the cap can be
  re-sent after a long gap — receiver idempotency must carry the load.
- One-shot, synchronous send per event; no batching, no async queue, no
  rate-limit awareness.

## Mapping: envelope key → common SIEM ingestion shapes

No vendor-specific output is produced; this is the mapping a receiver-side
adapter applies. Generic guidance only.

| Envelope key | CEF (ArcSight/Common Event Format) | OpenTelemetry-style log record |
|---|---|---|
| `event_id` | `CEF:0` `name`/deviceExternalId anchor; duplicate suppression key | `logRecord.observedID` / dedup key attribute `oaa.event_id` |
| `event_time` | CEF `rt` (receipt time), RFC3339 → epoch ms on ingest | `logRecord.timestamp` |
| `kind` | extension field `category` / `cat` | `logRecord.severityText` neutral; attribute `oaa.kind` |
| `org_id` | extension `cs1` (label: org) | Resource attribute `oaa.org_id` |
| `agent_id` | extension `suser` / `dhost` (subject host) | Resource attributes `oaa.agent_id` |
| `run_ref` | extension `cs2` (label: run) | Attribute `oaa.run_ref` |
| `trace_ref` | extension `requestContext` / `cs3` (label: trace) | Span/log `trace_id` linkage attribute `oaa.trace_ref` |
| `receipt_hash` | extension `fileHash`-style / `cs4` (label: receipt) | Attribute `oaa.receipt_hash` |
| `fields` (finding) | `severity` → severity 1–10 map (critical=10 … info=1); `name`=rule_id; `msg`=redacted explanation | Severity: critical→FATAL/ERROR, high→ERROR, medium→WARN, low→INFO, info→DEBUG; attributes `oaa.rule_id`, `oaa.rule_version`, `oaa.confidence`, `oaa.suppression_reason` |
| `fields` (verification/ correlation) | `name`=state, `msg`=discrepancy summary | Attribute `oaa.state` (`oaa.status`) |
| `fields` (evidence_summary) | custom counters as `cs5`/`cf1`+ | Attributes `oaa.summary.*` |

Notes: CEF has no native dedup key — ingest layers keyed on
`deviceExternalId + rt + name` collapse duplicates; keep `event_id` in an
extension (`cs*`) verbatim so suppression stays authoritative. OTel-style
receivers naturally carry arbitrary attributes — prefer the `oaa.*`
namespace. Never map `suppression_reason` into a severity-affecting field:
suppressed findings remain retained and reported (RULE-01 invariant).

## Gaps (not built in EXP-01)

- **Auth headers for real SIEMs**: no HMAC signing / API key / mTLS /
  OAuth2 client-credentials transport. Credentials must never enter the
  envelope (invariant); they belong in an injection point around `deliver`
  once a concrete receiver transport is chosen.
- **Schema registry**: envelope field evolution beyond v1 needs a registry
  (versioned field catalogue + receiver-facing JSON Schema for the envelope
  itself, analogous to `schemas/rules-config.schema.json`).
- **Rate limiting / batching**: no token-bucket, no adaptive backoff on
  429-with-Retry-After, no batched ingestion to cut request volume.
- **Dedup state durability**: single local JSON file; no compaction /
  shared store for multi-exporter deployments.