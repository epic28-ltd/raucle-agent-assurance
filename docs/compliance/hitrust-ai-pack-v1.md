# HITRUST AI Security Framework v1 pack

> **Scope disclaimer.** This pack is a *mapping* of the raucle-agent-assurance
> evidence plane to the HITRUST AI Security Assessment control topics
> relevant to AI agents: the HITRUST CSF v11 AI-specific control topics
> covering AI system inventory, AI change management, AI data protection
> and AI incident response. It is not, and must never be presented as,
> legal advice, a HITRUST assessment or certification, a validated or
> readiness finding, or any other claim of compliance. Every statement
> below is phrased as "mapped to": the mapping says what repository
> evidence exists and how far it goes - no further. Rows marked
> UNSUPPORTED are honest gaps, kept visible on purpose (the repo's
> compliance-honest invariant). The repository provides technical
> evidence only and makes no claim about any organisation's HITRUST
> readiness or certification status.

## What this pack is

The governance crosswalk (`ops/assurance-profiles/crosswalk.json`) maps
framework controls to real, offline-verifiable packet evidence, in the same
row structure used for the EU AI Act / HIPAA / PCI DSS / ISO 42001 / NIST
AI RMF mappings: one row per control, with an `evidence_field` pointing
into the assurance packet, an honest `status` (SUPPORTED / PARTIAL /
UNSUPPORTED), and a `basis` (or `unsat_reason`) anchoring the claim to the
repo artefact that backs it.

This pack reads out the HITRUST slice of that crosswalk as a v1 compliance
pack, organised into four AI control topic areas that follow the public
HITRUST AI assessment outlines, and names the export format a firm can
produce it with.

## Licence-restriction and numbering note

HITRUST CSF requirement statements are licence-restricted: HITRUST controls
material is proprietary and its text may not be reproduced without licence.
This pack therefore reproduces **no control text** - it references control
topics by descriptive id and short title only, exactly as carried in the
crosswalk rows. The topic structure (AI system inventory, AI change
management, AI data protection, AI incident response) follows the public
HITRUST AI assessment outlines rather than the licensed CSF text, and the
descriptive ids here are the repo's own, not HITRUST requirement-statement
ids. The mapping must be verified against the licensed HITRUST CSF (by a
HITRUST-licensed organisation) before any buyer-facing use: control
references and requirement alignments may differ from the public outline,
and versions of the CSF change (v11 sub-releases have extended AI coverage,
including agentic AI considerations). Until that verification is done,
this pack is an internal mapping of the evidence plane, not a HITRUST
position paper.

## Focus area 1: AI system inventory and accountability

| Crosswalk control | HITRUST AI mapping | Status | Evidence |
| --- | --- | --- | --- |
| `AI system inventory` | AI system inventory - Inventory of AI systems and the components that run them | PARTIAL | `coverage.gate_covered_tools`: the custody-coverage map (ops/assurance/config/coverage.yaml, ADR-0004) and the packet's coverage section enumerate every gated tool in the agent plane, so the technically-deployed surface has a machine-readable inventory; no organisation-wide register of AI systems, models or datasets exists in the repo. |
| `AI system accountability` | AI system accountability - Assigned accountability and ownership for AI systems | UNSUPPORTED | No named ownership, accountability or oversight-role record for AI systems exists in the evidence plane: roles and approval workflows are organisation-level artefacts (the same gap the ISO 42001 pack records for A.3.2). The gap is recorded, not papered over. |
| `AI third-party and inherited controls` | AI third-party and inherited controls - Third-party AI services and inherited control coverage | PARTIAL | `coverage.unverified_tools`: the packet's coverage list makes coverage gaps over the gated tool plane visible rather than silently passed, which is honest coverage accounting for third-party-connected tools; no shared-responsibility or inherited-controls record (in the HITRUST inheritance sense) exists in the repo. |

## Focus area 2: AI change management

| Crosswalk control | HITRUST AI mapping | Status | Evidence |
| --- | --- | --- | --- |
| `AI system change management` | AI system change management - Change management over AI systems and their controls | UNSUPPORTED | No change-approval register, impact documentation or sign-off workflow over AI systems exists in the repo or the evidence schema (the same gap the PCI DSS pack records for 6.5); reviewed-PR traces are repository practice, not an evidence plane field. The gap is recorded, not papered over. |
| `AI system change verification` | AI system change verification - Verification and validation of AI system behaviour under change | PARTIAL | `risk_annotations`: red-run suites (policy fuzz, gateway HTTP/MCP, tamper, forge) and the offline verifier exercise control behaviour with receipted outcomes and risk annotations, so control behaviour is verified against its requirements; the verified surface is the agent tool plane, not an AI model's outputs. |

## Focus area 3: AI data protection

| Crosswalk control | HITRUST AI mapping | Status | Evidence |
| --- | --- | --- | --- |
| `AI system data protection` | AI system data protection - Protection of AI system data (training, input, output) | UNSUPPORTED | The plane records actions, not data: no dataset classification, data-at-rest/in-transit protection or AI data-handling control exists in the evidence plane (the same gap the ISO 42001 pack records for Annex A.7); the redaction stage is a bounded-disclosure behaviour, not a data-protection control. The gap is recorded, not papered over. |
| `AI record integrity` | AI record integrity - Protection of AI records from improper alteration | SUPPORTED | `receipt_chain.receipt_hashes`: every gated tool call produces a sha256-pinned, tamper-evident receipt (receipts.jsonl, ADR-0001/0002) and the assurance packet revalidates content against its signing key offline, so alteration of records is detectable and verifiable. The packet's signing surface revalidates content against its own public key, giving post-quantum tamper-evidence of packet content (services/assurance_packet/packet.py). |

## Focus area 4: AI incident response

| Crosswalk control | HITRUST AI mapping | Status | Evidence |
| --- | --- | --- | --- |
| `AI logging and monitoring` | AI logging and monitoring - Logging and continuous monitoring of AI system activity | SUPPORTED | `receipt_chain.verified_count`: every gated tool call produces a receipt (receipts.jsonl) and the custody-coverage map plus deterministic security rules (services/rules SEC-001..SEC-011) monitor the plane continuously, so AI-system activity (the agent tool plane) is logged and monitored. |
| `AI incident detection and response updates` | AI incident detection and response updates - Detection of AI-specific security events feeding incident response | PARTIAL | `receipt_chain.invalid_or_missing_count`: missing or invalid receipts are first-class deterministic findings (SEC-001, SEC-002), so integrity incidents on the AI tool plane are detected and evidenced; no organisational incident playbooks, tabletop exercises or response process exists in the repo. |
| `AI incident recording` | AI incident recording - Recording of AI-specific security incidents that have occurred | UNSUPPORTED | No record of AI-specific security incidents, or of their specifics (threat type, impact, recovery), exists in the evidence plane: the plane records detections, not an incident lifecycle (the same gap the DORA pack records for Art 11 incident reporting). The gap is recorded, not papered over. |

## Evidence-export format reference

The pack above is derived from the crosswalk, and a machine-readable version
of the same mapping is produced by the GRC evidence-graph export:

- `tools/grc_export/export.py` emits a versioned, deterministic
  `grc_evidence_graph/v1` JSON document. Every HITRUST row becomes a
  control node with its status; edges named `evidence_satisfies_control` only
  exist where the crosswalk names a packet evidence field, and each carries
  the row's status, so a PARTIAL row can never read as SUPPORTED.
  UNSUPPORTED rows have no such edge - the gap is visible in the export
  itself. Output is vendor-neutral, `graph_content_sha256`-digested, and
  offline-verifiable.
- The underlying evidence fields live in the `agent_assurance_packet` shape
  (OV-1); packets are validated against governance profiles by
  `ops/assurance-profiles/validator.py`.

To produce a HITRUST view of a packet:

```bash
.venv/bin/python tools/grc_export/export.py --packet packet.json
# filter the nodes for framework == "HITRUST AI Security Framework" for this pack's slice
```

## What does NOT cleanly map to HITRUST AI controls (honest gaps)

- **Assessment and certification.** Nothing in this repository evidences,
  or could evidence, a HITRUST assessment outcome: no external assessor
  relationship, no validated assessment, no HITRUST quality review. The
  pack maps evidence; an assessment belongs to a HITRUST assessor working
  with the organisation, never to a repository.
- **Accountability and ownership.** Assigned ownership of AI systems is an
  organisational artefact; the evidence plane produces technical evidence
  about agent tool calls only. This pack makes no claim about who owns an
  AI system.
- **AI change management as an organisational process.** Approval
  registers, duty separation and sign-off workflows do not exist here; the
  plane verifies control behaviour after the fact, it does not govern
  change approval. This pack makes no claim about change governance.
- **AI data protection.** The plane records actions, not datasets; no
  training/input/output data-handling control is evidenced. This pack
  makes no claim about data protection of AI data.
- **Incident lifecycle beyond detection.** Detections are receipted
  findings; playbooks, tabletops and incident records are not. This pack
  makes no claim about incident response capability.
- **Retention and destruction.** Records are staged and re-verified, but no
  retention-period or destruction lifecycle control exists (the same gap
  the EU AI Act pack records for Art 19 and the ISO 42001 pack records for
  Clause 7.5).
- **Numbering verification.** Topic structure follows the public HITRUST
  AI assessment outlines, not the licensed CSF requirement statements; ids
  are descriptive, not HITRUST requirement-statement ids, and must be
  verified against the licensed CSF before any buyer-facing use.

## Verification

The consistency of this pack with the crosswalk is enforced by
`tests/assurance/test_hitrust_ai_pack.py`: every control topic id named here
must exist as a HITRUST crosswalk row with the same status, every topic area
must have rows, the pack copy must carry the mapped-to disclaimer with no
certification or compliance claims, no HITRUST control text may be
reproduced (ids and titles only), and the validator self-check must stay
empty.
