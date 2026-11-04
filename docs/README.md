# Open Agent Assurance: architecture documents

Status: imported planning documents (ARCH-01, 4 Nov 2026, raucle pinned v0.23.5 (`63edacd`), Langfuse v4.74.0 (`0845eed`), Phoenix v21.0.0), pending review before ADR status is upgraded to Accepted. Spike findings that ground them are collected in `docs/spikes/`.

## Contents

- `adr/0001-trust-model-and-evidence-plane.md`: two-plane evidence architecture, versioned trust roots, historic verification after key rotation, correlation authenticity.
- `adr/0002-event-contract.md`: canonical model (eight entities), dual-taxonomy adapter for OTel GenAI plus OpenInference, conformance fixtures as the portability mechanism.
- `adr/0003-backend-adapter.md`: Langfuse-first adapter, evidence index outside the backend, licence hygiene, three de-risking probes required before UI work.
- `threat-model/threat-model-v0.md`: ten threat scenarios across six trust boundaries, with controls mapped to plan backlog IDs and residual risks accepted in writing.

## Rules carried into the code

1. The companion never becomes the authority for tool permissions.
2. Canonical `{receipt_hash, jws}` bytes are preserved verbatim; derived state lives in the index only.
3. `valid` is never inferred from missing data; unknown, not-applicable and zero stay distinct.
4. Producers authenticate; correlation is a hint, and the signed `x_gate.trace_id` is authoritative where present.
5. Trust roots are versioned and retired keys are archived; every verification records verifier and trust-policy versions.
6. Metadata-only telemetry by default; redaction is tested, not promised.

## Pending review before build

- ADR status upgrade to Accepted after review.
- Trust-root registry schema (ADR 0001) implemented as a story, not sketched.
- Failure behaviour for evidence sink versus telemetry path still needs the named risk-owner decision (plan section 5).
- Name and trademark check for "Open Agent Assurance" before any public-facing use.