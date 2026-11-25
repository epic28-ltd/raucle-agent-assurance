# SOC 2 Trust Services Criteria mapping v1

> **Scope and reliance disclaimer.** This document maps the Open Agent Assurance evidence plane to SOC 2 Trust Services Criteria identifiers. It is an evidence crosswalk, not a SOC 2 report, audit opinion, readiness assessment, attestation, certification or claim of compliance. It does not assess an organisation’s full control environment or any customer deployment. A qualified independent service auditor determines scope, applicable criteria, control design and operating effectiveness.

## Basis and scope

This v1 covers the Common Criteria (CC1–CC9) and the additional Availability (A1), Confidentiality (C1), Processing Integrity (PI1) and Privacy (P1) criteria as a broad reference inventory. Applicability depends on service commitments, system boundaries and categories selected for an actual engagement; listing a category here does not assert that it applies. Criterion labels below are concise paraphrases for navigation, not reproduced AICPA TSC text. Confirm the current authoritative criteria and points of focus with AICPA materials and the engagement auditor.

Each row has one of three evidence-plane verdicts: SUPPORTED, PARTIAL or UNSUPPORTED. These are bounded statements about repository artefacts only. SUPPORTED does not mean a control is effective across a service or period. PARTIAL describes a narrow technical contribution. UNSUPPORTED means the repository has no suitable evidence field.

The machine-readable source is `ops/assurance-profiles/crosswalk.json`; the deterministic GRC export emits the same statuses in `grc_evidence_graph/v1`.

## Common Criteria — control environment (CC1)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `CC1.1` | Governance oversight and integrity | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC1.2` | Board oversight responsibilities | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC1.3` | Organisational structure and authority | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC1.4` | Competence and accountability | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC1.5` | Individual accountability | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Common Criteria — communication and information (CC2)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `CC2.1` | Internal and external communication | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC2.2` | Communication of objectives and responsibilities | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC2.3` | External communication | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Common Criteria — risk assessment (CC3)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `CC3.1` | Objectives and risk identification | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC3.2` | Risk analysis | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC3.3` | Fraud risk consideration | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC3.4` | Change-related risk assessment | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Common Criteria — monitoring activities (CC4)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `CC4.1` | Ongoing and separate evaluations | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC4.2` | Deficiency evaluation and communication | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Common Criteria — control activities (CC5)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `CC5.1` | Control activities selected and developed | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC5.2` | Technology general controls | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC5.3` | Policies and procedures | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Common Criteria — logical and physical access (CC6)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `CC6.1` | Logical access security | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC6.2` | Credential issuance and removal | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC6.3` | Authorisation and access provisioning | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC6.4` | Access removal and modification | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC6.5` | Physical access restrictions | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC6.6` | External threat protection | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC6.7` | Data transmission and movement | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC6.8` | Malicious software prevention | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Common Criteria — system operations (CC7)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `CC7.1 configuration monitoring` | Monitoring of system configuration and potential anomalies | SUPPORTED | `coverage.gate_covered_tools`: Per-tool custody coverage defaults to unverified unless the gate signed receipts (fail-visible default), and registry changes surface as SEC-006. |
| `CC7.2 anomaly detection` | Detection of anomalous events and response | SUPPORTED | `receipt_chain.invalid_or_missing_count`: SEC-001/002 catch missing and invalid receipts, SEC-003/004 catch denial-rate anomalies and tool-side success after a correlated deny, SEC-005/006 catch looping and capability drift. |
| `CC7.3` | Security event evaluation | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC7.4` | Incident response | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `CC7.5` | Recovery and business continuity | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Common Criteria — change management (CC8)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `CC8.1` | Change authorisation and implementation | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Common Criteria — risk mitigation (CC9)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `CC9.1 access risk mitigation` | Risk mitigation for the use of access credentials | PARTIAL | `coverage.unverified_tools`: Credential leases are observed on the custody plane for gate-covered tools (ADR-0004) with unverified tools reported fail-visible, but there is no vault-level credential custody control in the repo itself. |
| `CC9.2` | Business disruption risk mitigation | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Additional Availability criteria (A1)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `A1.1` | Availability commitments and capacity | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `A1.2` | Environmental and infrastructure protection | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `A1.3` | Recovery testing and restoration | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Additional Confidentiality criteria (C1)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `C1.1` | Confidential information identification and protection | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `C1.2` | Confidential information disposal | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Additional Processing Integrity criteria (PI1)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `PI1.1` | Processing integrity objectives | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `PI1.2` | System input completeness and accuracy | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `PI1.3` | Processing completeness and accuracy | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `PI1.4` | Output completeness and accuracy | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `PI1.5` | Data storage and retention integrity | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Additional Privacy criteria (P1)

| Crosswalk control | SOC 2 TSC mapping | Status | Evidence / gap |
| --- | --- | --- | --- |
| `P1.1` | Privacy notice and purpose communication | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `P1.2` | Choice and consent | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `P1.3` | Collection limitation | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `P1.4` | Use, retention and disposal limitation | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `P1.5` | Access and correction rights | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `P1.6` | Disclosure to third parties | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `P1.7` | Data quality | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |
| `P1.8` | Privacy-related monitoring and enforcement | UNSUPPORTED | The repository evidence plane does not produce the organisation-level policies, operating records, system configurations or independent assessment evidence needed to support this SOC 2 criterion. Agent-tool receipts and coverage data are not a substitute; the gap remains explicitly unclaimed. |

## Evidence export

Run the existing exporter against an assurance packet:

```bash
.venv/bin/python tools/grc_export/export.py --packet packet.json
```

Filter exported control nodes for `framework == "SOC 2"`. Unsupported rows remain visible as control nodes without evidence-satisfies-control edges. The export does not create an audit workpaper or establish operating effectiveness.

## Explicit exclusions and limitations

- **Organisation-level governance:** board oversight, risk appetite, policies, roles, competence, internal audit and management review are not established by this repository’s technical evidence plane.
- **Enterprise IT and facilities:** physical security, infrastructure hardening, identity lifecycle, backups, disaster recovery, vulnerability management and production change approvals require separate system and organisational evidence.
- **Service-specific scope:** availability, confidentiality, processing integrity and privacy criteria may or may not apply depending on actual commitments and services. Their inclusion here is not an applicability decision.
- **Period evidence:** repository fixtures and point-in-time packets do not establish control operation over a SOC 2 examination period.
- **Independent assurance:** no auditor testing, sampling, opinion or SOC 2 report is produced here.

This pack makes no claim that raucle-agent-assurance, its maintainers, any organisation or any deployment is SOC 2 compliant or has obtained a SOC 2 report.
