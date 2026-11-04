# ADR 0002: Event contract and canonical model

Status: Draft (pending review)
Date: 2026-11-04

## Context

The companion ingests two independent event families: OTel/OpenInference traces (via the collector, backend-first Langfuse v4.74.0) and raucle receipts (via the evidence plane). The plan's section 8 proposes eight canonical entities. The DISC-02 spike adds code-verified constraints, and the C workstream establishes that trace semantics are not a stable contract today.

Verified constraints this decision must respect:

- Envelope on disk is exactly `{receipt_hash, jws}`; verifiers reject extras.
- `x_gate.trace_id` is the signed correlation key; receipt index supports query by trace_id.
- OTel GenAI semconv: all documents marked Development at pinned commit `633cbb0`; no release tags exist; per-attribute stability badges; recent breaking changes (per-message events replaced by `*_ref`/message attributes; new `gen_ai.provider.name`, `gen_ai.response.status`). OpenInference (tag `v0.1.43`) requires `openinference.span.kind` and has no workflow/plan/handoff concept. Both taxonomies are non-equivalent and live simultaneously.
- Python instrumentation families are all pre-1.x (official 1.3b0, OpenInference instrumentors 0.x to 2.x).

## Decision

1. **Dual-taxonomy adapter.** The instrumentation adapter normalises both taxonomies into the companion's canonical model, carrying its own conversation join. Standard attributes pass through unchanged where both specs agree; companion-specific names live in a project attribute namespace (`oaa.*`) and are versioned by an envelope version field. Every fixture pins the spec commit SHA used to build it.

2. **Canonical entities** (adopting the plan's eight, with spike-grounded refinements):

   | Entity | Notes |
   |---|---|
   | Run | Keys: run_id, trace_id. `trace_id` mirrors raucle's signed field when the gateway path is used |
   | Span | operation_type, tool_invocation_id, tool_ref, model_ref, error. Content fields carry redaction state, never raw secrets |
   | Usage | tokens/cost as reported by the backend; pricing version recorded |
   | Evidence | `receipt_ref = receipt_hash`; never embeds receipt content, only references and digests |
   | Verification | status enum from ADR 0001; verifier_version and trust_policy_version mandatory |
   | Correlation | `matched, receipt_missing, trace_missing, ambiguous, late_arrival, duplicate`; matching_method recorded |
   | Finding | rule_id + rule_version + severity + confidence; findings reference evidence, not intuition; suppression history retained |
   | Evaluation | evaluator identity + version + uncertainty; advisory only, never enforcement input in MVP |

3. **Distinguishing absence, unknown, not-applicable and zero** is a schema-level requirement: nullable-and-differentiated fields, and a schema test that fails if any state collapses to null.

4. **Failure handling.** Out-of-order events, duplicates, retries, partial traces and clock skew are handled in the correlation service; duplicate delivery produces one logical index record while preserving every provenance artefact. Producer identity is authenticated at ingest and organisation is derived server-side; caller-supplied trace IDs are hints.

5. **Conformance fixtures are the portability mechanism.** Because `gen_ai.*` carries no release tags and has shown breaking changes, the canonical model is held stable by fixtures (valid, invalid, unknown_key, unsupported_schema, duplicate, late, missing), built per pinned spec SHA and run in CI. Spec bumps require a fixture update, not an adapter rewrite.

## Consequences

- Backend change (Langfuse to Phoenix to Tempo) touches only the adapter, per ADR 0003.
- Langfuse's ingestion flattening is a fidelity risk, mitigated by round-trip fixtures (backend matrix de-risking probe) before any UI work.
- Schema churn is a cost, not a catastrophe, but fixture maintenance is a recurring engineering line item.

## Alternatives considered

- Adopt OTel GenAI conventions as the canonical model alone: rejected, contract too unstable (Development status, untagged).
- Fork OpenInference: rejected by the plan's no-fork rule unless a documented extension gap makes it unavoidable.