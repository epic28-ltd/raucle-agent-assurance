# EU AI Act compliance pack v1

> **Scope disclaimer.** This pack is a *mapping* of the raucle-agent-assurance
> evidence plane to EU AI Act articles relevant to AI agents (transparency,
> logging and record-keeping, human oversight, robustness). It is not, and
> must never be presented as, legal advice, a conformity assessment, EU AI Act
> certification, or any other claim of compliance. Every statement below is
> phrased as "mapped to": the mapping says what repository evidence exists and
> how far it goes - no further. Rows marked UNSUPPORTED are honest gaps, kept
> visible on purpose (the repo's compliance-honest invariant).

## What this pack is

The governance crosswalk (`ops/assurance-profiles/crosswalk.json`) maps
framework controls to real, offline-verifiable packet evidence, in the same
row structure used for the NIST AI RMF / OWASP LLM Top 10 mapping: one row per
control, with an `evidence_field` pointing into the assurance packet, a
honest `status` (SUPPORTED / PARTIAL / UNSUPPORTED), and a `basis` (or
`unsat_reason`) anchoring the claim to the repo artefact that backs it.

This pack reads out the EU AI Act slice of that crosswalk as a v1 compliance
pack, organised by the four focus areas, and names the export format a firm
can produce it with.

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
