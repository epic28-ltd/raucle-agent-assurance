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

Run: `pytest tests/services/test_correlation.py` (raucle-free baseline stays green).