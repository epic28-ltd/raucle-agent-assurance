# ISO/IEC 42001 compliance pack v1

> **Scope disclaimer.** This pack is a *mapping* of the raucle-agent-assurance
> evidence plane to ISO/IEC 42001:2023 (AI management system, AIMS)
> requirements relevant to AI agents: the management-system clauses (Clauses
> 4 to 10) and Annex A control areas A.1 through A.10, with the records and
> operation controls carrying most of the coverage. It is not, and must never
> be presented as, legal advice, an ISO/IEC 42001 audit or certification, a
> conformity assessment, or any other claim of compliance: an evidence
> mapping is not certification, regulatory conformity or an independent
> audit. Every statement below is phrased as "mapped to": the mapping says
> what repository evidence exists and how far it goes - no further. Rows
> marked UNSUPPORTED are honest gaps (or, where the control is organisational
> and outside the evidence plane's remit, not-applicable entries with
> reasons), kept visible on purpose (the repo's compliance-honest invariant).
> The repository provides technical evidence only and makes no claim about
> any organisation's AIMS, its readiness for an audit, or its certification
> status.
>
> **Evidence-mapping metadata (crosswalk v2).** Every ISO 42001 row in the
> crosswalk now carries a `disposition` (mapped / gap / not-applicable), an
> owner slot written as `owner-pending Craig` (a named, unfilled assignment
> pending Craig - never an invented person), an `evidence_freshness`
> (`verified_at` date plus the git commit of the cited artifact at main;
> null for unmet gaps), a `system_version_scope` (repository
> epic28-ltd/raucle-agent-assurance, artifacts shipping in raucle v0.23.9,
> verified from raucle CHANGELOG "## 0.23.9 (2026-11-24)" and raucle
> pyproject `version = "0.23.9"`), and a `verification_status` (independent
> offline verification versus engineering-authored only). The deterministic,
> digest-bound export of the whole mapping table is
> `tools/grc_export/mapping_manifest.py` (run as `--profile manifest`).

## What this pack is

The governance crosswalk (`ops/assurance-profiles/crosswalk.json`) maps
framework controls to real, offline-verifiable packet evidence, in the same
row structure used for the EU AI Act / HIPAA / PCI DSS mappings: one row per
control, with an `evidence_field` pointing into the assurance packet, an
honest `status` (SUPPORTED / PARTIAL / UNSUPPORTED), and a `basis` (or
`unsat_reason`) anchoring the claim to the repo artefact that backs it.

This pack reads out the ISO 42001 slice of that crosswalk as a v1 compliance
pack, organised into four focus areas that follow the standard's structure
(AIMS context and leadership, risk assessment and treatment, support and
operation, performance evaluation and improvement), extended so that every
Annex A area A.1 through A.10 has at least one row, and names the export
format a firm can produce it with.

Numbering note: the standard's primary text is paywalled, so control wording
below is descriptive rather than verbatim. Clause numbering follows the ISO
harmonized management-system structure (Clauses 4 to 10) and Annex A control
numbering follows the published ISO/IEC 42001:2023 control list (38 controls
in nine areas, A.2 to A.10). The two ISO 42001 rows inherited from the
original crosswalk were renumbered to that structure: impact-assessment
documentation is A.5.3 and operation and monitoring is A.6.2.6. The
evidence-mapping extension (issue 113) adds area-level rows for A.1, A.4 and
A.7 plus corroborated sub-control rows (A.8, A.9, A.10) so that every Annex A
area A.1 through A.10 has at least one row, honestly disposed: mapped rows
cite artifacts that exist at main, gap rows name the missing evidence, and
out-of-scope organisational controls are marked not-applicable with reasons.
Confirm wording against the standard itself before any formal use.

## Focus area 1: AIMS context, leadership, policy and resources (Clause 4, Clause 5, A.1, A.2, A.3, A.4)

| Crosswalk control | ISO 42001 mapping | Status | Evidence |
| --- | --- | --- | --- |
| `A.1 general` | A.1 - consider and justify each Annex A control in an organisational statement of applicability | UNSUPPORTED | Out of the evidence plane's scope rather than a per-control artefact: A.1 directs the selection and justification of Annex A controls in an organisational statement of applicability, an AIMS document the repository does not produce and does not own. The A.2 to A.10 rows here are the technical slice this deployed agentic-gateway control plane can evidence; the organisational justification belongs to the deploying organisation's AIMS. |
| `Clause 4.3 AIMS scope` | Clause 4.3 - determining the scope of the AI management system | PARTIAL | `governance.ISO 42001`: ADRs (docs/adr/0001-0005) and the governance profiles declare the deliberately narrow scope of the evidence plane, and the packet carries the ISO 42001 mapping slot the firm fills; no organisation-level AIMS scope statement or interested-parties analysis exists in the repo. |
| `A.2.2 AI policy` | A.2.2 - an AI policy is established, documented and communicated by top management | UNSUPPORTED | No organisational AI policy artefact exists in the repo: the signed gate policies bind tool calls, they are not a top-management-approved AI policy communicated across an organisation. The gap is recorded, not papered over. |
| `A.3.2 AI roles and responsibilities` | A.3.2 - AI roles and responsibilities are defined and assigned | UNSUPPORTED | No AIMS roles, responsibilities or reporting lines exist in the evidence plane: there are no oversight-operator roles or approval workflows (the same gap the EU AI Act pack records for Art 14 human oversight). |
| `A.4.2 AI system inventory` | A.4.2 - the AI systems the organisation develops, procures or uses are recorded and kept current | PARTIAL | `agent_identity.agents`: the assurance packet inventorises every agent the gateway governs (agent identity plus capability chain, shape pinned by tests; `services/assurance_packet/packet.py`) and the custody-coverage map inventories the gated tool surface per agent. An inventory mechanism for gateway-governed agents only, not the deploying organisation's register of all AI systems. |

## Focus area 2: AI risk assessment and treatment (Clause 6, A.5)

| Crosswalk control | ISO 42001 mapping | Status | Evidence |
| --- | --- | --- | --- |
| `A.5.3 documentation of AI system impact assessments` | A.5.3 - documentation of AI system impact assessments | PARTIAL | `risk_annotations`: the GOV-01 scoped assurance report (ops/assurance/generate_report.py, structural no-claim guard) and the documented legal-compliance boundary provide assessment inputs, but no formal impact-assessment artefact is produced. |
| `Clause 6.1.3 AI risk treatment` | Clause 6.1.3 - AI risk treatment (controls selected to treat identified AI risks) | PARTIAL | `policy_proof_refs`: enforced, signed policies plus deterministic rules (services/rules SEC-001..SEC-011) treat the evidence plane's identified risks (unauthorised tool calls, tampered receipts, capability drift); no organisation-level AI risk register or treatment plan artefact exists. |

## Focus area 3: support, data, documentation and AI system operation (Clause 7, Clause 8, A.6, A.7, A.8)

| Crosswalk control | ISO 42001 mapping | Status | Evidence |
| --- | --- | --- | --- |
| `Clause 7.2 competence` | Clause 7.2 - competence of persons doing work that affects AI performance | UNSUPPORTED | No competence, training or awareness artefact for AI-related personnel exists in the repo; competence is an organisational control the evidence plane cannot produce. |
| `Clause 7.5 documented information` | Clause 7.5 - documented information required by the AIMS is controlled and retained | PARTIAL | `receipt_chain.verified_count`: receipt bytes are staged into the offline audit pack (ops/audit-pack/pack.py) and re-verified outside the production plane, so the AIMS's technical records can be kept and independently checked; no retention-period, archival or destruction lifecycle control exists in the repo. |
| `A.6.2.4 AI system verification and validation` | A.6.2.4 - AI system verification and validation | PARTIAL | `risk_annotations`: red-run suites (policy fuzz, gateway HTTP/MCP, tamper, forge) and the offline verifier exercise and verify control behaviour with receipted outcomes; no verification of an AI model against its requirements exists, the agent tool plane is the only verified surface. |
| `A.6.2.6 AI system operation and monitoring` | A.6.2.6 - AI system operation and monitoring | SUPPORTED | `coverage.gate_covered_tools`: custody-coverage map (ops/assurance/config/coverage.yaml, ADR-0004) plus deterministic security rules (services/rules SEC-001..SEC-011) monitor every gated tool call continuously. |
| `A.6.2.8 AI system recording of event logs` | A.6.2.8 - AI system recording of event logs | SUPPORTED | `receipt_chain.verified_count`: every gated tool call produces a sha256-pinned, tamper-evident receipt (receipts.jsonl, ADR-0001/0002); the chain is independently re-verified offline and missing or invalid receipts are first-class findings (SEC-001, SEC-002). |
| `A.7 data for AI systems` | A.7 - data for AI systems (area objective: provenance, quality, preparation, protection and PII for development data) | UNSUPPORTED | Out of the evidence plane's scope: the gateway governs inference-time tool calls and produces tamper-evident receipts for them; it neither trains, fine-tunes nor evaluates models, so no development-data provenance, quality, preparation or training-data PII artefact exists in the repository. Development-data controls belong to the deploying organisation's AIMS; recorded honestly rather than claimed. |
| `A.8.2 AI system documentation and information for users` | A.8.2 - system documentation and information for users of the AI system, including its behaviour and limits | PARTIAL | `policy_proof_refs`: the repository documents the control plane for its users and auditors (auditor-quickstart.md, ADRs, the offline audit pack's digest-bound claims.md plus manifest.json) and signed policies declare each agent's constraints; the plane documents itself and its controls, it produces no per-AI-system user documentation or model explainability material. |

## Focus area 4: performance evaluation, improvement, responsible use and suppliers (Clause 9, Clause 10, A.9, A.10)

| Crosswalk control | ISO 42001 mapping | Status | Evidence |
| --- | --- | --- | --- |
| `Clause 9.1 monitoring, measurement and evaluation` | Clause 9.1 - monitoring, measurement, analysis and evaluation of the AIMS | PARTIAL | `coverage.gate_covered_tools`: the custody-coverage map and its receipted-share coverage metric plus deterministic findings rules continuously measure the evidence plane's technical performance; no AIMS-wide performance-evaluation programme exists. |
| `Clause 9.2 internal audit` | Clause 9.2 - internal audit of the AIMS at planned intervals | UNSUPPORTED | No internal AIMS audit programme, audit schedule or management review exists in the repo; the offline pack verifier re-verifies technical evidence, it does not audit a management system. |
| `Clause 10.2 continual improvement` | Clause 10.2 - continual improvement of the suitability and effectiveness of the AIMS | UNSUPPORTED | Findings are produced and evidenced (SEC-001..SEC-011 findings, red-run findings) but no documented continual-improvement or corrective-action process over the management system exists in the repo. |
| `A.9.4 intended use of the AI system and prevention of out-of-scope use` | A.9.4 - intended use of the AI system, and prevention or guidance against out-of-scope use | PARTIAL | `policy_proof_refs`: signed, versioned gate policies pin each agent's intended tool scope and the deterministic rules layer (services/rules SEC-001..SEC-011) denies receipt-less or unverified-tool invocations, with uncovered tools fail-visible, so out-of-scope tool use is prevented and evidenced at the point of use; the declared scope covers the agent tool plane, not the AI system's application-domain intended use, which remains the operator's declaration. |
| `A.10.3 suppliers` | A.10.3 - suppliers: assessment, contractual AI terms and ongoing monitoring of third-party AI providers | UNSUPPORTED | Out of the evidence plane's scope: supplier assessment, contractual terms and organisational monitoring are procurement controls no deployment artefact can substitute. The plane does pin its own upstream dependency provenance technically (RAUCLE_DISTRIBUTION_PIN in packages/raucle-adapter, tripwired by tests/conformance/test_pin_tripwire.py), but that is a dependency-provenance record for one in-repo supplier relationship, not supplier management; the packet carries no supplier field. |

## Evidence-export format reference

The pack above is derived from the crosswalk, and a machine-readable version
of the same mapping is produced by the GRC evidence-graph export:

- `tools/grc_export/export.py` emits a versioned, deterministic
  `grc_evidence_graph/v1` JSON document. Every ISO 42001 row becomes a
  control node with its status; edges named `evidence_satisfies_control` only
  exist where the crosswalk names a packet evidence field, and each carries
  the row's status, so a PARTIAL row can never read as SUPPORTED.
  UNSUPPORTED rows have no such edge - the gap is visible in the export
  itself. Output is vendor-neutral, `graph_content_sha256`-digested, and
  offline-verifiable.
- The underlying evidence fields live in the `agent_assurance_packet` shape
  (OV-1); packets are validated against governance profiles by
  `ops/assurance-profiles/validator.py`.

To produce an ISO 42001 view of a packet:

```bash
.venv/bin/python tools/grc_export/export.py --packet packet.json
# filter the nodes for framework == "ISO 42001" for this pack's slice
```

## What does NOT cleanly map to ISO/IEC 42001 (honest gaps)

- **Certification and the certification body.** Nothing in this repository
  evidences, or could evidence, ISO/IEC 42001 certification: no accredited
  certification body relationship, no stage audits, no statement of
  applicability. The pack maps evidence; an audit and any certificate belong
  to a certification body working with the organisation, never to a
  repository.
- **Organisational AIMS governance (Clauses 4 to 5, A.2, A.3).** Top
  management commitment, an organisational AI policy, AIMS roles and
  reporting of concerns are organisational artefacts; the evidence plane
  produces technical evidence about agent tool calls only.
- **Competence, awareness and communication (Clauses 7.2 to 7.4).** No
  training, awareness or communication artefact exists in the repo.
- **Internal audit and management review (Clauses 9.2 and 9.3).** No AIMS
  audit programme or management review exists; the offline verifier is a
  technical re-verification, not an audit of a management system.
- **Continual improvement (Clause 10).** Findings exist; a corrective-action
  process over the management system does not.
- **Annex A areas not mapped in v1.** Resources (A.4), data for AI systems
  (A.7), information for interested parties (A.8), use of AI systems (A.9)
  and third-party relationships (A.10) are mapped only where the evidence
  plane has something honest to say. The A.4 and A.7 areas in particular have
  no evidence here: the plane records actions, not datasets or resources.
- **Retention and destruction.** Records are staged and re-verified, but no
  retention-period or destruction lifecycle control exists (the same gap the
  EU AI Act pack records for Art 19).
- **Numbering verification.** Clause and control numbering follows published
  control lists for ISO/IEC 42001:2023, not the paywalled primary text;
  wording is descriptive, not verbatim, and should be confirmed against the
  standard before formal use.

## Verification

The consistency of this pack with the crosswalk is enforced by
`tests/assurance/test_iso42001_pack.py`: every control id named here must
exist as an ISO 42001 crosswalk row with the same status, every focus area
must have rows, the pack copy must carry the mapped-to disclaimer with no
compliance or certification claims, and the validator self-check must stay
empty.
