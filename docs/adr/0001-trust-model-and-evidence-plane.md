# ADR 0001: Trust model and evidence plane

Status: Draft (review pending; decision recorded 4 Nov 2026: fail-visible audit-persistence failure — index records an unavailable state and raises SEC-007; nothing silently degrades)
Date: 2026-11-04
Deciders: EPIC28 / Open Agent Assurance companion team

## Context

The companion correlates raucle signed receipts with agent OpenTelemetry traces. The DISC-02 spike (findings at `~/Projects/oaa-spike-4nov/DISC-02-findings.md`, raucle pinned v0.23.5 `63edacd`) established the verified facts this decision rests on:

- Gate receipts for allow AND deny are compact JWS signed Ed25519 documents. Signing input is `b64url(JCS(header)) + "." + b64url(JCS(payload))` plus the signature. Canonical JSON (JCS, RFC 8785) is enforced byte-equality on re-parse in strict mode. `receipt_hash = "sha256:" + sha256(compact JWS)`. Immutability is by construction; append-only sinks; no API mutates an emitted receipt.
- The on-disk envelope is exactly `{"receipt_hash", "jws"}`. The verifier (`raucle.registry.unknown_envelope_fields`) rejects any extra envelope field.
- `trace_id` is a first-class signed field: accepted as `X-Trace-Id` header or `check_tool_call(trace_id=...)`, written into the signed `x_gate` block, indexed (`idx_receipts_trace`).
- Verification is importable offline: `ProvenanceVerifier(public_keys: dict[kid to PEM], capabilities=...).verify_chain(path)`. Trust roots are passed in-band; no server dependency.
- Key lifecycle (workstreams C+D findings): rotation uses versioned issuer identities plus registry revoke. Revocation is gate-time only; there is no CRL. Historic receipts remain verifiable after rotation only if the retired public keys are archived. RFC 3161 hash-only TSA anchoring exists in three modes; optional Ed25519-signed checkpoints.
- The verification state space the plan proposes: `valid, invalid, unknown_key, unsupported_schema, pending, unavailable, not_applicable`.

Without a decision on trust-root versioning, every key rotation degrades archived receipts from `valid` to `unknown_key` silently. That was the C+D workstream's principal new design requirement.

## Decision

1. **Evidence plane versus index plane.** The companion operates two stores. The evidence plane preserves canonical signed artefacts verbatim: `{"receipt_hash", "jws"}` JSONL, byte-identical in and out, in private object storage with integrity-checked retrieval. The index plane (PostgreSQL) stores only derived state: verification results, correlation states, field extracts for query. Nothing derived is ever treated as a substitute for the bytes; disputes resolve against the evidence plane.

2. **Versioned trust roots.** The companion stores its own trust-root registry keyed by `(key_id, valid_from, valid_until)`, sourced from raucle's versioned issuer identities. Retired keys are never deleted, only marked current/retired. Verification of any receipt selects trust roots by the key_id inside the JWS header and the receipt's event time, not solely by current trust status:

   - Signature verifies against the key that signed it (regardless of retirement) and that key was trusted at event time: `valid`.
   - Key present but revoked at event time: `invalid` (revocation-at-event-time is recorded separately from expiry of current trust).
   - key_id absent from the archive: `unknown_key`, distinguished in queries from `invalid`.
   - Schema or extension family unsupported by this verifier build: `unsupported_schema`.
   - Every verification records: `verification_status, checked_at, verifier_version, trust_policy_version`, and the exact checks performed.

3. **Trust roots are administered, not self-asserted.** The companion never mints receipts and never holds private keys of agents or the gateway. Trust-root changes are an administrative role (see threat model role separation).

4. **Timestamp anchoring.** Where deployed, TSA anchoring is recorded in the index as a reference to raucle's TSA mechanism; the companion does not re-anchor. Event-time trust evaluation is possible without TSA because raucle receipts carry their own signing context; TSA strengthens non-repudiation, not verification.

5. **Correlation authenticity.** The trace-side `trace_id` is treated as an authenticated correlation hint, not authentication: producers authenticate to the ingest API and the organisation identity is derived server-side. The signed `x_gate.trace_id` is authoritative where present; a trace claiming a receipt it does not resolve to yields `ambiguous` or `trace_missing`, never auto-verified.

## Consequences

- DECIDED 4 Nov 2026: evidence-sink / audit-persistence failure is FAIL VISIBLE by default: the index marks affected ranges `unavailable` and the SEC-007 assurance-degradation rule fires. Ingest continues to accept producer traffic (bounded local buffer) but no verification result is ever emitted without the corresponding evidence check. Fail-closed halt is a per-deployment override, not the default.

- Rotation is a non-event for historic evidence: archived keys keep `valid` receipts verifiable indefinitely, and the workstream C+D gap is closed by design rather than by upstream change.
- Verifier builds are pinned; upgrading the verifier triggers a re-verification sweep recorded with the new `verifier_version`.
- Storage cost includes the key archive; small, bounded, but must appear in the cost model.
- Upstream change (new `x_` extension, receipt schema bump) is absorbed by the `unsupported_schema` state plus conformance fixtures, not by emergency forks.
- Honest-coverage posture: a `valid` result asserts integrity and authority within the recorded trust model only. It never asserts the action was safe, appropriate, or compliant. Reports say so.

## Alternatives considered

- Rely on raucle's registry revocation alone: rejected, no CRL exists and gate-time revocation does not address historic verification.
- Re-sign or transform receipts into an internal format: rejected outright; mutates canonical evidence, breaks the hash, and was always prohibited by the plan.
- Single current trust root: rejected, silently degrades archive verification at first rotation.