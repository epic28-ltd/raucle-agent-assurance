# Threat model: Open Agent Assurance companion

Status: Draft (pending review)
Date: 2026-11-04
Method: asset-centred; per-trust-boundary STRIDE; residual risks stated explicitly.

## Assets

| Asset | Value at risk |
|---|---|
| Canonical receipts (`{receipt_hash, jws}`) | Trust root of all assurance output |
| Trust-root registry | Authenticity of verification results |
| Trace telemetry | Confidentiality of workflow metadata; integrity of correlation |
| Evidence index (Postgres) | Integrity of derived state; availability |
| Analyst credentials (UI) | Read access to privileged-call history |
| Companion config (redaction rules, rules files) | Silent weakening of detection and redaction |
| Companion reputation as honest reporter | The differentiator itself |

## Trust boundaries

1. Agent runtime to collector (untrusted producer: a compromised agent lies)
2. Collector to backend/index (network, credentials)
3. raucle gateway to evidence sink (issuer controlled by operator)
4. Companion internal (index, rules, UI)
5. Analyst to UI (human access)
6. Evidence plane vs index plane (derived state never substitutes for bytes)

## Key threat scenarios and controls

**T1 Compromised agent forges or drops telemetry.** The agent can delete its own traces, fabricate spans, or claim foreign trace_ids. Controls: producer authentication at ingest; server-side organisation derivation; the signed `x_gate.trace_id` inside gate receipts is authoritative; rules SEC-001 (receipt missing after grace) and SEC-004 (tool-side success after correlated deny) surface the discrepancy. Residual: an agent that never calls the gate on a path the gateway cannot observe leaves a coverage gap the companion can only mark, not close. Stated honestly: this is the product's coverage boundary, not a detection failure.

**T2 Compromised collector or ingest path.** Telemetry interception or injection between runtime and backend. Controls: TLS, bounded payloads, deduplication, replay-resistant ingest. Residual: a collector that silently drops evidence produces `unavailable` states; the ingest-outage metrics (OBS-02) make loss visible rather than silent, which is the acceptance target.

**T3 Forged or tampered receipts.** Ed25519 signatures plus JCS byte-equality plus `receipt_hash` recomputation make mutation detectable (verified in the spike: any byte change breaks the hash). Controls: SEC-002 rule fires on verification failure; tampered fixtures in CI. Residual: none cryptographic; denial-of-service by flooding invalid receipts is rate-limited.

**T4 Evidence sink or verifier down.** Do not silently weaken anything. Enforcement stays with raucle regardless of companion health (structural separation; ADR 0001). Verification backlog beyond threshold raises SEC-007 (assurance degradation, surfaced to the operator). Failure to persist audit itself is the named risk-owner decision per the plan, not something the companion improvises.

**T5 Malicious analyst account or SSRF class abuse in UI.** All model and tool content renders as hostile text: no stored script execution, no auto-link resolution, no image fetch from span content. Role separation (telemetry-read, evidence-read, key-administration, configuration-change are distinct). Content quarantine on SEC-008 hits before investigators open raw content.

**T6 Verification result manipulation via correlation ambiguity.** An attacker floods ambiguous events to drown real gaps. Controls: explicit correlation states (`ambiguous` separated from `matched`), duplicates collapsed to one logical record, per-worksource identity, rate budgets per producer.

**T7 Trust-root substitution.** If trust-root administration is compromised, everything reads valid. Controls: admin role separation, change logging on trust policy (trust_policy_version recorded on every verification), and the honest-compliance wording in every report: a valid result asserts integrity and authority within the trust model, never safety or compliance.

**T8 Prompt injection against evaluators or rule workers.** Retrieved content and tool outputs are untrusted inputs (documented in the plan's evaluation strategy). Controls: evaluators have no tools and no secrets; evaluator prompts are versioned and never executed against side effects; LLM-based evaluators are off by default in MVP.

**T9 Telemetry leaks confidential data.** The plan's PRIV-01: metadata-only default, SDK redaction before export, collector checks as defence in depth, seeded-secret fixtures in CI, content-hash is not treated as anonymisation.

**T10 Companion becomes the authority.** The monitoring path never grants or revokes permissions. Failure of the companion or collector must not change raucle gate decisions. This is the structural control the plan commits to, tested in OPS-01 scenarios.

## Residual risks accepted for the MVP

- Coverage boundary: uninstrumented tool paths and ungated executions are outside the evidence; reports declare it.
- Behavioural baselines are signals, not proof of compromise.
- Langfuse flattening and spec churn can reduce fidelity; fixtures catch regressions but the backend remains a moving dependency.
- Single-organisation deployment first: multi-tenancy threats (cross-tenant leakage) are out of scope until later scope work.

Open review questions: redaction rule ownership; retention reconciliation with raucle records-lifecycle (do not break signed chains on deletion); UK GDPR role analysis (deferred to the workstream F/G phase with legal review).