# COR-01 findings — minimal correlation service

Status: PASS (engine + tests + optional live smoke)
Date: 2026-11-04
Code: `services/correlation/` (package `oaa-correlation`, stdlib-only),
tests `tests/services/test_correlation*.py` (raucle-free).

## Design

- Pure, offline `reconcile(receipts, traces, config, at)` reconciling an
  index of receipt records (receipt_hash, trace_id from the signed
  `x_gate.trace_id`, decision, event_time; OBS-01 p5 / EVD receipts.jsonl
  pattern) against trace-side records (trace_id, tool_invocation,
  observed_at, event window).
- Index rows only: the engine never receives canonical `{receipt_hash,
  jws}` envelope bytes. Synthetic receipts in tests are hand-built INDEX
  rows with fake hashes and an explicit `synthetic: true` marker.
- `load_receipt_index()` opens index JSONL strictly read-only and asserts
  sha256 of the raw bytes before/after (invariant 1, read-only-mode proof).
- Grace window (`CorrelationConfig.grace_seconds`, default 30s) absorbs
  out-of-order arrival on both sides. In-grace unpaired records stay
  **open** — counted in `CorrelationResult.pending`, never reported as
  `receipt_missing`/`trace_missing` (invariant 2: absence is a gap, not a
  result). Pass `at=None` to reconcile as if every window had closed.

## State table (ADR-0002 Correlation entity; decided per trace_id)

| Condition | State |
|---|---|
| 1 distinct receipt in trace window ± grace | `matched` |
| N deliveries of the SAME receipt_hash (collapsed 1 logical record, all provenance kept) | `duplicate` |
| ≥2 DISTINCT receipt hashes for one trace-side record | `ambiguous` (never silently resolved) |
| receipt event_time outside window ± grace | `late_arrival` (still correlated; direction in `notes`) |
| trace side has no receipt, grace elapsed | `receipt_missing` |
| receipt side has no trace (incl. missing x_gate trace_id), grace elapsed | `trace_missing` |
| nothing to pair yet, grace still running | **open** → `pending` count only |

Precedence: ambiguous > duplicate > late_arrival > matched.

## Tests (10 new, raucle-free; suite 22 passed / 1 skipped — 12P+1S baseline kept)

- Table-driven over every state: matched, duplicate, ambiguous,
  late_arrival, receipt_missing, trace_missing, out-of-order in grace,
  out-of-order beyond grace (`tests/services/test_correlation.py`).
- Grace-boundary tests both directions (pending → terminal after grace).
- Duplicate collapse preserves per-delivery provenance (3 deliveries of one
  hash → one record, provenance list intact).
- sha256-immutability of a loaded index file via the read-only-mode assert.
- Optional live smoke (`tests/services/test_correlation_smoke.py` →
  `integrations/langfuse_smoke.py`): verified against the running local
  stack (Langfuse v4.74.0, obs01 compose, web 127.0.0.1:3301). Posted a
  NUMERIC score `cor01.correlation` on synthetic trace
  `cor01-smoke-trace-0001` whose comment carries
  `cor01;receipt_hash=sha256:...01;synthetic=true`; readback matched
  verbatim; engine emitted `matched` offline first. Skip path exercised by
  construction (stack-down → pytest.skip). Note: the backend 404s scores on
  unknown trace ids, so the smoke creates the synthetic trace first
  (`POST /api/public/traces`), idempotent-checked.

## Gaps toward a Postgres-backed COR service (effort left to EVD-02 indexing)

- `reconcile` is in-memory and O(n) per run; a real service needs an
  ingest-and-persist model, so EVD-02's Postgres-backed receipt index
  (query by trace_id + event_time) is the natural substrate.
- No idempotent upsert of CorrelationRecords; no `matching_method` column
  beyond `notes` free text.
- Late/missing re-evaluation on every ingest (reconciliation sweep) is
  unimplemented — currently one-shot with an explicit `at`.
- Ambiguity requires human/ingest review; no quarantine table/API yet.
- Multi-organisation identity: caller-supplied trace IDs are hints; org
  derivation must happen at authenticated ingest (invariant 4) — out of
  scope here.

## Verdict

COR-01 PASS: engine offline-testable, every ADR-0002 correlation state
exercised, evidence-store immutability invariant asserted, live attach/read
round-trip verified on the pinned local stack, ruff clean, pytest green,
baseline not regressed.