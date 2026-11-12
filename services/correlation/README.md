# correlation service (COR-01)

Minimal, offline-testable correlation engine reconciling receipt **index
rows** against trace-side records, per ADR-0002 (Correlation entity).

- Engine: `src/oaa_correlation/core.py` — stdlib only, pure function
  `reconcile()`. States: `matched | duplicate | ambiguous | late_arrival |
  receipt_missing | trace_missing`. Out-of-order events absorbed by a
  configurable grace window; in-grace unpaired records stay *open* (counted
  in `CorrelationResult.pending`), never reported as missing.
- Index rows only: the engine never sees canonical evidence bytes
  (`{receipt_hash, jws}` envelopes stay verbatim in the evidence store —
  companion invariant 1). `load_receipt_index()` opens index JSONL
  read-only and asserts sha256 before/after.
- Synthetic receipts are hand-built **test index rows only** (fake hashes +
  explicit `synthetic: true` marker), never evidence-store fixtures.
- Optional smoke vs the local Langfuse stack:
  `integrations/langfuse_smoke.py` (skips cleanly without the stack).
  Keys come from the obs01 env file, never committed.
- Coverage (R1): `src/oaa_correlation/coverage.py` — ONE number computed
  from the engine's own reconciliation states: `receipted_share =
  receipted / total` over **observed agent actions** (the ADR-0002
  trace-side records). A record is *receipted* when its terminal
  correlation state carries a receipt (`matched`, `duplicate`,
  `late_arrival`, `ambiguous`); a record whose receipt never arrived past
  grace (`receipt_missing`) is *out_of_gate*. Buckets partition the plane
  (`total = receipted + out_of_gate + pending`; in-grace `pending` is
  disclosed, never folded). Receipt-side-only `trace_missing` records
  never touch the action number. The same response flags (deterministic,
  no synthetic data): `bypass_candidates` — out-of-gate actions, trace
  plane only, never a confirmed bypass without a tool-side or custody
  vantage (ADR-0004); `shadow_agents` — agents whose observed actions all
  minted zero receipts; `uninstrumented_tools` — tools observed acting
  with zero receipted actions anywhere in the window. Read from the
  assurance surface as `GET /coverage/{org}` (investigation UI; unknown
  org renders 404 *unavailable*, never a claimed zero).

Run: `pytest tests/services/test_correlation.py` (raucle-free baseline stays green).