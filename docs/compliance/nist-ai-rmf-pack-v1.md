# NIST AI RMF compliance pack v1

> **Scope disclaimer.** This pack is a *mapping* of the raucle-agent-assurance
> evidence plane to the NIST AI Risk Management Framework (AI RMF 1.0) core
> functions (GOVERN, MAP, MEASURE, MANAGE) relevant to AI agents, with
> records, monitoring and control-efficacy evidence carrying most of the
> coverage. It is not, and must never be presented as, legal advice, a
> NIST AI RMF conformance assessment, a maturity rating, or any other claim
> of compliance. Every statement below is phrased as "mapped to": the
> mapping says what repository evidence exists and how far it goes - no
> further. Rows marked UNSUPPORTED are honest gaps, kept visible on purpose
> (the repo's compliance-honest invariant). The repository makes no claim
> about any organisation's adoption of the framework, its profile selection,
> or the maturity of its AI risk management.

## What this pack is

The governance crosswalk (`ops/assurance-profiles/crosswalk.json`) maps
framework controls to real, offline-verifiable packet evidence, in the same
row structure used for the EU AI Act / HIPAA / PCI DSS mappings: one row per
control, with an `evidence_field` pointing into the assurance packet, an
honest `status` (SUPPORTED / PARTIAL / UNSUPPORTED), and a `basis` (or
`unsat_reason`) anchoring the claim to the repo artefact that backs it.

This pack reads out the NIST AI RMF slice of that crosswalk as a v1
compliance pack, organised by the four core functions, and names the export
format a firm can produce it with. Category and subcategory wording follows
the published NIST AI 100-1 core tables, with punctuation normalised; row
titles are descriptive, not verbatim quotes. The subcategory numbers carry
the mapping; confirm wording against the NIST publication before any formal
use.

Evidence-mapping metadata (crosswalk v2): every NIST AI RMF row in the
crosswalk now also carries a `disposition` (mapped / gap / not-applicable),
an owner slot written as `owner-pending Craig` (a named, unfilled assignment
pending Craig - never an invented person), an `evidence_freshness`
(`verified_at` date plus the git commit of the cited artifact at main; null
for unmet gaps), a `system_version_scope` (repository
epic28-ltd/raucle-agent-assurance, artifacts shipping in raucle v0.23.9,
verified from raucle CHANGELOG "## 0.23.9 (2026-11-24)" and raucle pyproject
`version = "0.23.9"`), and a `verification_status` (independent offline
verification versus engineering-authored only). The deterministic,
digest-bound export of the whole mapping table is
`tools/grc_export/mapping_manifest.py` (run as `--profile manifest`). An
evidence mapping is not certification, regulatory conformity or an
independent audit; this pack makes no such claim.

## Related mappings (existing, not invented here)

- The same crosswalk already carries an OWASP LLM Top 10 slice (LLM01,
  LLM03, LLM06, LLM08 rows) - the repo's existing OWASP testing surface,
  mapped with the same honest verdicts. This pack reuses that mapping where
  the functions overlap and adds nothing to it.
- The raucle gate repository (epic28-ltd/raucle) publishes its own
  alignment documents for the OWASP Top 10 for Agentic Applications and the
  NIST AI Agent Standards Initiative; gate-side primitives live there,
  evidence-plane fields live here.
- No OWASP AI Testing Guide crosswalk exists in this repository today. This
  pack does not invent one; recording such a crosswalk is future work and
  would carry its own honest verdicts.

## Focus area 1: GOVERN (policies, inventory and roles for AI risk)

| Crosswalk control | NIST AI RMF mapping | Status | Evidence |
| --- | --- | --- | --- |
| `GOVERN 1.1 policies` | GOVERN 1.1 - legal and regulatory requirements involving AI are understood, managed and documented | PARTIAL | `governance.NIST AI RMF`: ADRs, the runbook and the compliance-honest reporting boundary document requirements handling; the packet carries mapping slots but no requirements register. |
| `GOVERN 1.6 AI system inventory mechanisms` | GOVERN 1.6 - mechanisms are in place to inventory AI systems, resourced per organisational risk priorities | PARTIAL | `coverage.gate_covered_tools`: the custody-coverage map is an inventory mechanism for the agent's tool surface, fail-visible when a tool is not under gate custody (ADR-0004, SEC-006); it inventories tools per agent, not the organisation's AI systems. |
| `GOVERN 2.1 roles and responsibilities` | GOVERN 2.1 - roles, responsibilities and lines of communication for AI risk are documented and clear | UNSUPPORTED | No AI risk-management roles, responsibilities or lines of communication are documented in the evidence plane; no oversight-operator or accountability-role artefact exists (the same gap the EU AI Act pack records for Art 14). |

## Focus area 2: MAP (context, scope and risk controls)

| Crosswalk control | NIST AI RMF mapping | Status | Evidence |
| --- | --- | --- | --- |
| `MAP 3.3 targeted application scope` | MAP 3.3 - targeted application scope is specified and documented | PARTIAL | `policy_proof_refs`: signed, versioned policies pin each agent's targeted tool scope and constraints, and receipts evidence what actually ran inside it; the documented scope covers the agent tool plane only, not the system's intended application context, benefits or costs. |
| `MAP 4.2 internal risk controls` | MAP 4.2 - internal risk controls for components of the AI system, including third-party AI technologies, are identified and documented | PARTIAL | `capability_chain`: enforced policies and deterministic rules (services/rules SEC-001..SEC-011) are identified, documented risk controls for the agent tool plane (ADRs 0001-0005); no controls for non-tool components such as the model layer or third-party AI technologies are identified in the evidence plane. |

## Focus area 3: MEASURE (metrics, evaluation and monitoring)

| Crosswalk control | NIST AI RMF mapping | Status | Evidence |
| --- | --- | --- | --- |
| `MEASURE 1.2 effectiveness of controls` | MEASURE 1.2 - appropriateness of AI metrics and effectiveness of existing controls are regularly assessed and updated | SUPPORTED | `risk_annotations`: red-run suites measure control efficacy directly: policy fuzz, gateway HTTP, mcp, tamper and forge attempts are receipted, counted and ingested as findings. |
| `MEASURE 2.5 validity and reliability` | MEASURE 2.5 - the AI system to be deployed is demonstrated to be valid and reliable | UNSUPPORTED | No validity or reliability measurement of an AI system exists in the evidence plane: red-run suites measure attack resistance of the gate's controls (the MEASURE 1.2 and MEASURE 2.7 rows), not model validity, accuracy or generalisability. The gap is recorded, not papered over. |
| `MEASURE 2.7 security and resilience evaluation` | MEASURE 2.7 - AI system security and resilience are evaluated and documented | PARTIAL | `risk_annotations`: red-run tamper, forge and policy-fuzz suites evaluate the gate's attack resistance and are ingested as documented findings; resilience beyond attack resistance (fail-safe behaviour, graceful degradation of the agent as a whole) is not evaluated. |
| `MEASURE 2.10 privacy risk examination` | MEASURE 2.10 - privacy risk of the AI system is examined and documented | UNSUPPORTED | Findings never carry content (INDEX-PLANE only) and no privacy-risk examination or disclosure-scanning control exists in the evidence plane (the same gap the crosswalk records for OWASP LLM06). |

## Focus area 4: MANAGE (prioritisation, response and third-party monitoring)

| Crosswalk control | NIST AI RMF mapping | Status | Evidence |
| --- | --- | --- | --- |
| `MANAGE 2.3 response to unknown risks` | MANAGE 2.3 - procedures are followed to respond to and recover from a previously unknown risk when it is identified | UNSUPPORTED | Findings are produced and evidenced but no remediation workflow, response or recovery procedures or ticketing integration exists in the repo; detection is honest, response is out of scope. |
| `MANAGE 3.1 third-party risk monitoring` | MANAGE 3.1 - AI risks and benefits from third-party resources are regularly monitored, and risk controls are applied and documented | PARTIAL | `coverage.unverified_tools`: per-tool custody coverage observes tool-side calls with uncovered tools reported fail-visible (ADR-0004, SEC-006), monitoring the third-party tool surface; no supplier risk assessment or third-party AI technology register exists in the repo. |

## Evidence-export format reference

The pack above is derived from the crosswalk, and a machine-readable version
of the same mapping is produced by the GRC evidence-graph export:

- `tools/grc_export/export.py` emits a versioned, deterministic
  `grc_evidence_graph/v1` JSON document. Every NIST AI RMF row becomes a
  control node with its status; edges named `evidence_satisfies_control`
  only exist where the crosswalk names a packet evidence field, and each
  carries the row's status, so a PARTIAL row can never read as SUPPORTED.
  UNSUPPORTED rows have no such edge - the gap is visible in the export
  itself. Output is vendor-neutral, `graph_content_sha256`-digested, and
  offline-verifiable.
- The underlying evidence fields live in the `agent_assurance_packet` shape
  (OV-1); packets are validated against governance profiles by
  `ops/assurance-profiles/validator.py`.

To produce a NIST AI RMF view of a packet:

```bash
.venv/bin/python tools/grc_export/export.py --packet packet.json
# filter the nodes for framework == "NIST AI RMF" for this pack's slice
```

## What does NOT cleanly map to the AI RMF core (honest gaps)

- **MAP coverage is thin by design.** Context, benefits and costs (MAP 1),
  categorisation (MAP 2) and impacts on individuals, groups, communities and
  society (MAP 5) have no evidence: the plane maps tool-scope risk, not
  societal or individual impact.
- **Validity, reliability and privacy.** MEASURE 2.5 and MEASURE 2.10 stay
  UNSUPPORTED: attack-resistance and records evidence says nothing about
  model validity or privacy risk to individuals.
- **Response, recovery and decommissioning.** MANAGE 2.3 (response to
  previously unknown risks) and GOVERN 1.7 (safe decommissioning processes)
  have no evidence: the plane detects and records, it does not respond,
  recover or retire agents.
- **Organisational GOVERN categories.** GOVERN 2 (accountability
  structures), GOVERN 3 (workforce diversity), GOVERN 4 (risk culture) and
  GOVERN 5 (engagement with relevant AI actors) are organisational; the
  evidence plane produces technical evidence only.
- **Adoption and maturity questions.** The pack maps evidence to
  subcategories; it says nothing about an organisation's adoption of the
  framework, its profile selection, or any maturity rating.
- **Related mappings.** The OWASP LLM Top 10 slice of the same crosswalk
  (LLM01, LLM03, LLM06, LLM08) is the repo's existing OWASP testing mapping
  and is reused, not duplicated; no OWASP AI Testing Guide crosswalk exists
  in this repository and this pack does not invent one.

## Verification

The consistency of this pack with the crosswalk is enforced by
`tests/assurance/test_nist_ai_rmf_pack.py`: every control id named here must
exist as a NIST AI RMF crosswalk row with the same status, every core
function must have rows, the pack copy must carry the mapped-to disclaimer
with no adoption or compliance claims and no vendor names, and the validator
self-check must stay empty.
