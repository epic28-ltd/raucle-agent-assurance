<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-0005: Gate identity is a required correlation field

Date: 4 November 2026
Status: ACCEPTED

## Context

The suite is designed for deployments with many gate instances: one gate per
agent runtime, service or team, each minting receipts from its own signing
keys. The evidence model already supports this (self-contained JWS receipts,
trust roots selected at event time), but the correlation index treated gate
identity as implicit: nothing stopped receipts from different gates being
attributed to the wrong workflow, and coverage reporting had no per-gate
dimension.

## Decision

`ReceiptRecord` (the correlation index row) carries a REQUIRED `gate_id` field.

- Non-synthetic (evidence-backed) rows MUST set `gate_id`; construction fails
  otherwise. This is enforced in the dataclass, so every ingest path inherits
  the requirement.
- Synthetic index rows (explicit `synthetic: true` markers, never evidence)
  may omit it.
- Correlation must never silently merge records across gate identities; where
  a gate_id is absent on a real receipt, verification proceeds (the receipt
  itself is intact) but the row is not correlation-attributable, which is a
  coverage state, not a valid state.

## Consequences

- Ingest loaders pass `gate_id` from index rows; the evidence plane records
  the issuing gate for every receipt it indexes (demo evidence plane records
  `gateway` where the deployment runs a single gate).
- Per-gate coverage reporting (gate count, receipts/second, coverage per gate)
  becomes a query on existing rows rather than a schema change.
- Any future ingest endpoint must reject rows without gate identity for
  evidence-backed records; the ingest-side check joins the ingest contract.
- The queue-before-ingest backlog item (scaling many gate streams) remains
  deferred until a pilot workload justifies it.

## Related

- ADR-0001 (trust model and evidence plane)
- ADR-0002 (canonical model)
- docs/architecture integration contract (issuer_ref, trust roots)