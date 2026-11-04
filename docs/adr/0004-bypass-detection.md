# ADR 0004: Gate-circumvention detection and independent vantage points

Status: Draft (pending review)
Date: 2026-11-04
Deciders: EPIC28 / companion team. Requirement stated by Craig 4 Nov 2026: the companion (Raucle Agent Assurance) must detect attempts by an agent to circumvent the Raucle Agent Trust gate; if agents can freely route around the gate, the suite fails its core promise.

## Context

Raucle Agent Trust's own trust claim is deliberately scoped: its guarantees hold on gated paths (the plan's S1 correction records this boundary). A compromised or misbehaving agent therefore has one fundamental circumvention route: **never invoke the gate on the path it actually uses**. The companion cannot prevent that route at the assurance layer, but it can detect it, provided there exists at least one vantage point the agent does not control. This ADR defines the detection model.

Three vantage points exist in the architecture, with different trust properties:

| Vantage | Controlled by agent? | What it shows |
|---|---|---|
| G: gate receipts (signed, offline-verifiable) | No (raucle gateway) | What was requested, allowed, denied, under whose authority |
| A: tool-side audit records | Only if the agent owns the tool host | What actually executed against the tool |
| C: credential/custody events (raucle credential leases) | No (lease issuer) | Which credentials were leased, to whom, for what |
| T: trace telemetry (OpenInference/OTel) | Yes — fully spoofable | Workflow narrative only |

Design rule: **bypass detection must never rely on T alone.** A spoofed trace showing a tool call without a receipt is indistinguishable from a spoofed trace showing a receipt without a tool call. Trace-derived signals are coverage checks; authoritative bypass signals come from A and C.

## Decision

1. **Reconciliation as the detection mechanism.** The companion reconciles G against A (and C where deployed) by agent identity, tool and time window, using the same state machine as ADR 0002 correlation. Detection of circumvention is: an A-side (or C-side) event that no G-side receipt corroborates, inside a window where the tool was privileged and the agent's credentials should have been leased. The absence of a *trace* record is never a bypass signal; the absence of a *tool-side* receipt is.

2. **Bypass candidate is one category, two causes.** A reconciled gap may be a genuine bypass attempt or an instrumentation/evidence gap (tool audit missing, clock skew, late arrival). The companion therefore distinguishes:
   - `bypass_suspected`: A-side execution observed, no gate receipt, agent identity and tool confirmed privileged, beyond grace.
   - `evidence_gap`: no tool-side record exists either; nothing confirms the call happened at all.
   `bypass_suspected` requires human investigation by default; no automatic attribution of intent in MVP findings.

3. **Credential custody is the strong control and it lives at the enforcement layer.** Where raucle credential leases are in the deployment, a privileged invocation *requires* a leased capability, whose issuance is itself receipted. In that deployment shape, direct tool use without a lease is structurally impossible for leased credentials, and any A-side event using a credential with no matching C-side lease is `bypass_suspected` with high confidence. This is the honest limit of the suite: **detection strength scales with custody coverage**. Tools with their own ambient credentials (out of lease custody) reduce the companion to audit-log reconciliation; the deployment documentation must state custody coverage per tool.

4. **Rules added to the RULE-01 set:**

   | ID | Rule | Interpretation |
   |---|---|---|
   | SEC-009 | Privileged tool-side execution observed with no corroborating gate receipt (beyond grace) | Candidate circulation around the gate; investigate; distinguish from instrumentation gap |
   | SEC-010 | Credential consumed with no matching issued lease (custody deployments) | High-confidence custody-violation signal |
   | SEC-011 | Agent config/producer authentication anomaly at ingest (credential rotation without re-auth, changed producer identity mid-chain) | Possible attempt to fragment identity across gate boundaries |

5. **Suite claim wording.** Fixed phrasing for all surfaces: Raucle Agent Trust proves what was allowed to run on gated paths; Raucle Agent Assurance detects what ran outside them, to the extent that independent tool-side or custody vantage points exist. Coverage is declared per tool, never implied.

## Consequences

- Deployment model gains a first-class field: custody coverage map (which tools are leased, which are audit-reconciled only, which are unobserved).
- The reconciliation window for A/G must tolerate clock skew and tool-side audit batching; `late_arrival` semantics apply symmetrically.
- Findings never state "the agent bypassed the gate"; they state the observed discrepancy and its confidence class. Reviewer judgement is the attribution step (consistent with the plan's non-goals).
- Upstream candidates: exposing tool-side audit event interfaces for reconciliation is a raucle integration task, not companion work; the companion consumes documented interfaces only.

## Alternatives considered

- Trace-instrumented interception proxies for every tool: rejected for MVP (operational weight, and the plan's non-goal of becoming the enforcement path); retained as a later-scope custody enforcement option.
- Relying on agent attestation of its own tool calls: rejected outright (attast-self semantics; the agent is the compromised party in the threat model).