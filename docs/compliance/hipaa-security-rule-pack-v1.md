# HIPAA Security Rule compliance pack v1

> **Scope disclaimer.** This pack is a *mapping* of the raucle-agent-assurance
> evidence plane to HIPAA Security Rule (45 CFR Part 164, Subpart C,
> 164.312) technical safeguard standards relevant to AI agents (audit
> controls, integrity, access control, transmission security). It is not, and
> must never be presented as, legal advice, a HIPAA compliance assessment,
> HIPAA Security Rule certification, or any other claim of compliance. Every
> statement below is phrased as "mapped to": the mapping says what repository
> evidence exists and how far it goes - no further. Rows marked UNSUPPORTED
> are honest gaps, kept visible on purpose (the repo's compliance-honest
> invariant). The repository contains no PHI and makes no claim about how any
> deployment handles, stores or transmits it.

## What this pack is

The governance crosswalk (`ops/assurance-profiles/crosswalk.json`) maps
framework controls to real, offline-verifiable packet evidence, in the same
row structure used for the EU AI Act / DORA / SOC 2 mappings: one row per
control, with an `evidence_field` pointing into the assurance packet, a
honest `status` (SUPPORTED / PARTIAL / UNSUPPORTED), and a `basis` (or
`unsat_reason`) anchoring the claim to the repo artefact that backs it.

This pack reads out the HIPAA slice of that crosswalk as a v1 compliance
pack, organised by the four 164.312 focus areas, and names the export format
a firm can produce it with.

## Focus area 1: audit controls

| Crosswalk control | HIPAA mapping | Status | Evidence |
| --- | --- | --- | --- |
| `164.312(b) audit controls` | 164.312(b) - hardware, software and procedural mechanisms that record and examine activity in information systems containing or using PHI | SUPPORTED | `receipt_chain.verified_count`: tamper-evident receipt chain over every gated tool call, independently re-verified offline (ops/audit-pack/pack.py); missing or invalid receipts are first-class findings (SEC-001, SEC-002). |

## Focus area 2: integrity

| Crosswalk control | HIPAA mapping | Status | Evidence |
| --- | --- | --- | --- |
| `164.312(c)(1) integrity` | 164.312(c)(1) - policies and procedures to protect records from improper alteration or destruction | PARTIAL | `receipt_chain.receipt_hashes`: sha256 content digests pin recorded activity and the verifier re-validates the whole chain. Scoped to the evidence plane's own records; no PHI integrity claim. |

## Focus area 3: access control

| Crosswalk control | HIPAA mapping | Status | Evidence |
| --- | --- | --- | --- |
| `164.312(a)(1) access control` | 164.312(a)(1) - technical measures guarding access (unique user identification, emergency access, automatic logoff and encryption are the addressable specifications) | PARTIAL | `coverage.unverified_tools`: privileged tools bound to signed policies with a recorded capability chain (policy_proof_refs, capability_chain); every tool not under gate custody reported fail-visible (SEC-006). |

## Focus area 4: transmission security

| Crosswalk control | HIPAA mapping | Status | Evidence |
| --- | --- | --- | --- |
| `164.312(e)(1) transmission security` | 164.312(e)(1) - technical measures guarding data in transit over electronic communications networks | UNSUPPORTED | No field evidences protection of data in transit: no transport encryption, channel integrity or network access control artefact exists. The gap is recorded, not papered over. |

## Evidence-export format reference

The pack above is derived from the crosswalk, and a machine-readable version
of the same mapping is produced by the GRC evidence-graph export:

- `tools/grc_export/export.py` emits a versioned, deterministic
  `grc_evidence_graph/v1` JSON document. Every HIPAA row becomes a
  control node with its status; edges named `evidence_satisfies_control` only
  exist where the crosswalk names a packet evidence field, and each carries
  the row's status, so a PARTIAL row can never read as SUPPORTED. UNSUPPORTED
  rows have no such edge - the gap is visible in the export itself. Output is
  vendor-neutral, `graph_content_sha256`-digested, and offline-verifiable.
- The underlying evidence fields live in the `agent_assurance_packet` shape
  (OV-1); packets are validated against governance profiles by
  `ops/assurance-profiles/validator.py`.

To produce a HIPAA view of a packet:

```bash
.venv/bin/python tools/grc_export/export.py --packet packet.json
# filter the nodes for framework == "HIPAA" for this pack's slice
```

## What does NOT cleanly map to the HIPAA Security Rule (honest gaps)

- **Technical vs administrative and physical safeguards** - 164.312 is the
  technical safeguards standard and the evidence plane is a technical plane,
  but HIPAA's Security Rule obligations run through administrative and
  physical safeguards as well (164.308 risk management and training,
  164.310 facility controls, business associate agreements). No repository
  artefact satisfies an administrative or physical safeguard, and this pack
  does not map them.
- **No PHI handling claims** - every row above records what the evidence
  plane can prove about the agent's tool calls. The repo contains no PHI and
  makes no claim about how a deployment's PHI-bearing systems store or
  transmit it; a firm's own HIPAA risk analysis is outside every row in this
  pack.
- **Addressable specifications** - unique user identification, emergency
  access procedures, automatic logoff and encryption of stored data
  (164.312(a)(2)) have no evidence fields; the access control row claims only
  the agent tool surface slice.
- **Transmission security** - recorded activity is tamper-evident, which
  supports the audit controls row; nothing evidences the transport channel
  itself, so the transmission security row is UNSUPPORTED.
- **Identities and authentication** - receipts bind agent identities to the
  gate's signing key; there is no user-identity directory, authentication
  strength or MFA evidence, and no access-review artefact in the plane.
- **Classification questions** - the pack maps safeguards without asserting
  whether an agent is a business associate tool, part of a covered entity's
  systems, or in scope at all; scope is a legal judgement the evidence plane
  explicitly does not attempt.

## Verification

The consistency of this pack with the crosswalk is enforced by
`tests/assurance/test_hipaa_pack.py`: every control id named here must exist
as a HIPAA crosswalk row with the same status, and the validator self-check
must stay empty.
