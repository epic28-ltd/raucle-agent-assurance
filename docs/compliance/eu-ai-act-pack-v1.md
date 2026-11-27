# EU AI Act compliance pack v1

> **Scope disclaimer.** This pack is a *mapping* of the raucle-agent-assurance
> evidence plane to EU AI Act articles relevant to AI agents (transparency,
> logging and record-keeping, human oversight, robustness, technical
> documentation, data governance, AI literacy). It is not, and must never be
> presented as, legal advice, a conformity assessment, EU AI Act
> certification, or any other claim of compliance: an evidence mapping is not
> certification, regulatory conformity or an independent audit. Every
> statement below is phrased as "mapped to": the mapping says what repository
> evidence exists and how far it goes - no further. Rows marked UNSUPPORTED
> are honest gaps (or, where the obligation is outside the evidence plane's
> remit, not-applicable entries with reasons), kept visible on purpose (the
> repo's compliance-honest invariant).
>
> **Legal review inputs.** Applicability determinations for EU AI Act
> obligations in this pack - which articles attach to a given deployment, and
> whether an engagement makes the plane part of a provider's or deployer's
> regulated system - are LEGAL REVIEW INPUTS, not determinations. This
> repository records evidence and honestly reports where evidence is missing;
> every EU AI Act row also carries an `applicability_status` of "not
> determined: legal review input" in the crosswalk. Only qualified legal
> review can determine applicability, role (provider/deployer) and risk
> class.
>
> **Evidence-mapping metadata (crosswalk v2).** Every EU AI Act row in the
> crosswalk now carries a `disposition` (mapped / gap / not-applicable), an
> owner slot written as `owner-pending Craig` (a named, unfilled assignment
> pending Craig - never an invented person), an `evidence_freshness`
> (`verified_at` date plus the git commit of the cited artifact at main; null
> for unmet gaps), a `system_version_scope` (repository
> epic28-ltd/raucle-agent-assurance, artifacts shipping in raucle v0.23.9,
> verified from raucle CHANGELOG "## 0.23.9 (2026-11-24)" and raucle pyproject
> `version = "0.23.9"`), and a `verification_status` (independent offline
> verification versus engineering-authored only). The deterministic,
> digest-bound export of the whole mapping table is
> `tools/grc_export/mapping_manifest.py` (run as `--profile manifest`).

## What this pack is

The governance crosswalk (`ops/assurance-profiles/crosswalk.json`) maps
framework controls to real, offline-verifiable packet evidence, in the same
row structure used for the NIST AI RMF / OWASP LLM Top 10 mapping: one row per
control, with an `evidence_field` pointing into the assurance packet, a
honest `status` (SUPPORTED / PARTIAL / UNSUPPORTED), and a `basis` (or
`unsat_reason`) anchoring the claim to the repo artefact that backs it.

This pack reads out the EU AI Act slice of that crosswalk as a v1 compliance
pack, organised into five focus areas (the original four plus a technical
documentation, data governance and AI literacy area), and names the export
format a firm can produce it with.

## Focus area 1: logging and record-keeping

| Crosswalk control | Article mapping | Status | Evidence |
| --- | --- | --- | --- |
| `Art 12(1) logging` | Art 12(1) - automatically generated logs of events | SUPPORTED | `receipt_chain.verified_count`: tamper-evident receipt chain over gated tool calls; invalid or missing receipts are first-class findings (SEC-001, SEC-002). |
| `Art 19 record-keeping of logs` | Art 19 - providers/deployers keep the logs | PARTIAL | Receipt bytes are staged into the offline audit pack (`ops/audit-pack/pack.py`) and re-verified outside the production plane, so records can be kept and checked. No retention-period control exists in the repo. |

## Focus area 2: transparency

| Crosswalk control | Article mapping | Status | Evidence |
| --- | --- | --- | --- |
| `Art 13(1)-13(3) transparency to deployers` | Art 13 - information for deployers | PARTIAL | `policy_proof_refs`: signed policies declare which tools the agent may run and under what rules; receipts show what it actually did. No deployer-facing documentation artefact is produced. |
| `Art 50(1) transparency to users` | Art 50(1) - disclosing AI interaction to end users | UNSUPPORTED | Nothing in the packet schema or repo evidences that end users were informed they were interacting with an AI system. |

## Focus area 3: human oversight

| Crosswalk control | Article mapping | Status | Evidence |
| --- | --- | --- | --- |
| `Art 14 human oversight` | Art 14 - human oversight measures | UNSUPPORTED | No oversight-operator roles, approval workflows or human-in-the-loop evidence fields exist in the packet schema or repo. |

## Focus area 4: robustness

| Crosswalk control | Article mapping | Status | Evidence |
| --- | --- | --- | --- |
| `Art 15(1) robustness and accuracy` | Art 15(1) - robustness, accuracy, cybersecurity | PARTIAL | `risk_annotations`: red-run findings (policy fuzz, tamper, forge suites) and denial-rate/bypass rules measure attack resistance. No formal accuracy standard or robustness certificate exists in the evidence plane. |

## Focus area 5: AI system technical documentation, data governance and AI literacy

| Crosswalk control | Article mapping | Status | Evidence |
| --- | --- | --- | --- |
| `Art 11 technical documentation` | Art 11 - technical documentation of the AI system kept up to date | PARTIAL | `receipt_chain.verified_count`: the offline audit pack (`ops/audit-pack/pack.py`) builds a reproducible, digest-bound technical document of the gateway plane's control evidence (claims.md plus a manifest.json of per-file sha256) and `tools/verifier/verify_pack.py` re-verifies it offline. It documents the gateway control plane only, not a full AI system technical file in the Art 11 sense. |
| `Art 10 data governance` | Art 10 - data governance and bias management for training, validation and testing data sets | UNSUPPORTED | Out of the evidence plane's scope: the gateway governs inference-time tool calls; training, validation and testing data sets never enter it, so no data-governance or bias-management artefact exists in the repository. Relevance is conditional (the Art 10 obligations attach to high-risk AI systems) and any such determination is a legal review input, undetermined here. |
| `Art 4 AI literacy` | Art 4 - AI literacy of staff and other persons operating AI systems on providers'/deployers' behalf | UNSUPPORTED | Out of the evidence plane's scope: AI literacy is an organisational training and awareness obligation resting on the deploying organisation's staff; the plane produces receipts, findings and audit documents and has no notion of personnel competence. Recorded honestly as a deployment-organisation obligation. |

## Evidence-export format reference

The pack above is derived from the crosswalk, and a machine-readable version
of the same mapping is produced by the GRC evidence-graph export:

- `tools/grc_export/export.py` emits a versioned, deterministic
  `grc_evidence_graph/v1` JSON document. Every EU AI Act row becomes a
  control node with its status; edges named `evidence_satisfies_control` only
  exist where the crosswalk names a packet evidence field, and each carries
  the row's status, so a PARTIAL row can never read as SUPPORTED. UNSUPPORTED
  rows have no such edge - the gap is visible in the export itself. Output is
  vendor-neutral, `graph_content_sha256`-digested, and offline-verifiable.
- The underlying evidence fields live in the `agent_assurance_packet` shape
  (OV-1); packets are validated against governance profiles by
  `ops/assurance-profiles/validator.py`.

To produce an EU AI Act view of a packet:

```bash
.venv/bin/python tools/grc_export/export.py --packet packet.json
# filter the nodes for framework == "EU AI Act" for this pack's slice
```

## What does NOT cleanly map to the AI Act (honest gaps)

- **Art 14 human oversight** - the evidence plane is gate-and-receipt based;
  it proves what the agent did and that nothing ran outside the gate, but it
  has no model of who supervises the agent, no approval workflow and no
  human-in-the-loop evidence field.
- **Art 50(1) transparency to users** - proving agent actions is not proving
  user-facing disclosure; no labelling or disclosure artefact exists.
- **Art 19 record-keeping, retention** - records can be staged and verified,
  but no retention-period policy or enforcement (e.g. the six-month default)
  exists in the repo.
- **Art 13 deployer-facing documentation** - policies and receipts are
  machine-facing; no instructions-for-use or technical-documentation artefact
  is generated.
- **Art 15 accuracy** - attack-resistance evidence says nothing about
  accuracy; there is no accuracy benchmark or robustness certificate in the
  evidence plane.
- **Classification questions** - the pack maps articles without asserting
  whether an agent is a high-risk AI system under Art 6; scope classification
  is a legal judgement the evidence plane explicitly does not attempt.

## Verification

The consistency of this pack with the crosswalk is enforced by
`tests/assurance/test_eu_ai_act_pack.py`: every control id named here must
exist as a crosswalk row with the same status, and the validator self-check
must stay empty.
