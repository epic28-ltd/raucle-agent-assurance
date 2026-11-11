# PCI DSS compliance pack v1

> **Scope disclaimer.** This pack is a *mapping* of the raucle-agent-assurance
> evidence plane to PCI DSS v4.0.1 requirements relevant to AI agents
> (Requirement 10 logging, Requirement 8 identity, Requirement 2 secure
> configurations, Requirement 6 secure software development and change
> control). It is not, and must never be presented as, legal advice, a PCI DSS
> assessment, an attestation of compliance, a Report on Compliance, or any
> other claim of compliance. Every statement below is phrased as "mapped to":
> the mapping says what repository evidence exists and how far it goes - no
> further. Rows marked UNSUPPORTED are honest gaps, kept visible on purpose
> (the repo's compliance-honest invariant). The repository makes no claim that
> any agent runs in, or is scoped to, a cardholder data environment.

## What this pack is

The governance crosswalk (`ops/assurance-profiles/crosswalk.json`) maps
framework controls to real, offline-verifiable packet evidence, in the same
row structure used for the EU AI Act / DORA / SOC 2 mappings: one row per
control, with an `evidence_field` pointing into the assurance packet, a
honest `status` (SUPPORTED / PARTIAL / UNSUPPORTED), and a `basis` (or
`unsat_reason`) anchoring the claim to the repo artefact that backs it.

This pack reads out the PCI DSS slice of that crosswalk as a v1 compliance
pack, organised by the four requirement focus areas, and names the export
format a firm can produce it with.

## Focus area 1: logging (Requirement 10)

| Crosswalk control | PCI DSS mapping | Status | Evidence |
| --- | --- | --- | --- |
| `10.2 audit logging of access and events` | Requirement 10.2 - audit logging of internal access and events, records carrying the user, the event, date and time, success or failure | PARTIAL | `receipt_chain.verified_count`: gated tool calls logged with the acting agent identity, the event (allow or deny) and a tamper-evident hash; records carry no payload content (bounded disclosure). User-account and configuration-change events are outside the plane's scope. |
| `10.4 log review and anomaly response` | Requirement 10.4 - logs reviewed, anomalies promptly addressed | PARTIAL | `receipt_chain.invalid_or_missing_count`: deterministic rules examine the receipt stream continuously (SEC-001/002, SEC-003/004, SEC-005/006) and the audit pack re-verifies the bytes off-system. |
| `10.5 audit log retention` | Requirement 10.5 - audit log history retained | UNSUPPORTED | The audit pack stages and re-verifies receipt bytes, but no retention policy, period control or archival lifecycle exists in the repo. |

## Focus area 2: identity and authentication (Requirement 8)

| Crosswalk control | PCI DSS mapping | Status | Evidence |
| --- | --- | --- | --- |
| `8.2 user identification and accounts` | Requirement 8.2 - unique identification established before access is granted | PARTIAL | `receipt_chain.receipt_hashes`: every receipt signed by the gate identity and binding the acting agent identity, verifiable offline. Agent-plane identification only; no user-account lifecycle controls. |
| `8.3/8.4 strong authentication and MFA` | Requirements 8.3 and 8.4 - strong authentication with MFA for access into the cardholder data environment | UNSUPPORTED | No authentication-strength, factor or MFA evidence field exists in the packet schema or repo. |

## Focus area 3: secure configurations (Requirement 2)

| Crosswalk control | PCI DSS mapping | Status | Evidence |
| --- | --- | --- | --- |
| `2.2 secure configurations` | Requirement 2.2 - system components secured in line with accepted configuration standards | PARTIAL | `policy_proof_refs`: the agent tool surface bound to signed, versioned policy artefacts; new privileged tools at release fail visibly (SEC-006). No OS, container or service hardening baseline artefact. |

## Focus area 4: secure development and change control (Requirement 6)

| Crosswalk control | PCI DSS mapping | Status | Evidence |
| --- | --- | --- | --- |
| `6.2 secure software development` | Requirement 6.2 - software developed securely, with changes reviewed by individuals other than the original author | PARTIAL | `governance.PCI DSS` mapping slot: changes to this repo land only through reviewed, CI-gated pull requests with DCO sign-offs, contracts pinned by deterministic tests and ADRs; no per-change reviewer-independence or approval artefact exists in the evidence plane. |
| `6.5 change control` | Requirement 6.5 - changes to system components managed through documented change control | UNSUPPORTED | No change-approval register, impact documentation, duty-separation or sign-off record exists in the repo or the evidence schema. |

## Evidence-export format reference

The pack above is derived from the crosswalk, and a machine-readable version
of the same mapping is produced by the GRC evidence-graph export:

- `tools/grc_export/export.py` emits a versioned, deterministic
  `grc_evidence_graph/v1` JSON document. Every PCI DSS row becomes a
  control node with its status; edges named `evidence_satisfies_control` only
  exist where the crosswalk names a packet evidence field, and each carries
  the row's status, so a PARTIAL row can never read as SUPPORTED. UNSUPPORTED
  rows have no such edge - the gap is visible in the export itself. Output is
  vendor-neutral, `graph_content_sha256`-digested, and offline-verifiable.
- The underlying evidence fields live in the `agent_assurance_packet` shape
  (OV-1); packets are validated against governance profiles by
  `ops/assurance-profiles/validator.py`.

To produce a PCI DSS view of a packet:

```bash
.venv/bin/python tools/grc_export/export.py --packet packet.json
# filter the nodes for framework == "PCI DSS" for this pack's slice
```

## What does NOT cleanly map to PCI DSS (honest gaps)

- **No cardholder data environment claims** - the evidence plane can only
  prove things about the agent tool plane recorded through the gate. It says
  nothing about any deployment's cardholder data handling, CDE scoping,
  segmentation or network controls; an agent operating inside a CDE is a
  question for the firm's own scoping process, not for this pack.
- **User-account and identity events** - Requirement 10.2 enumerates events
  such as account creation, elevation, disable and delete; the receipt chain
  logs tool calls only, so the logging and identity rows are PARTIAL and user
  lifecycle logging stays a gap.
- **Log retention** - no 12-month retention control or online-archive
  discipline exists in the repo (the UNSUPPORTED 10.5 row).
- **Authentication strength and MFA** - no factor, token or MFA evidence
  field exists, so nothing can evidence 8.3/8.4 posture (UNSUPPORTED).
- **Hardening baselines** - signed policies bound only the agent tool
  surface; no OS, container or service configuration baseline artefact exists
  for the 2.2 row beyond that slice.
- **Per-change review records** - the repo's changes land through reviewed,
  CI-gated pull requests with DCO sign-offs, but the evidence plane produces
  no reviewer-independence or change-approval artefact for 6.2, and no
  change-control register for 6.5.
- **Time synchronisation** - receipts carry host time; no consistent time
  source discipline (Requirement 10.6) is evidenced by the plane.

## Verification

The consistency of this pack with the crosswalk is enforced by
`tests/assurance/test_pci_dss_pack.py`: every control id named here must
exist as a PCI DSS crosswalk row with the same status, and the validator
self-check must stay empty.
