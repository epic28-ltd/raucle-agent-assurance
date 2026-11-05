# OV-4 governance profiles and crosswalk

What a LASR auditor can now claim because this exists: release gating against
declared governance standards, with every framework mapping pointing at real,
offline-verifiable raucle evidence, or stating honestly that none exists.

## Files

- `profiles.yaml`: `basic` vs `regulated` governance profiles. Each declares
  required framework mapping slots and required crosswalk controls, plus
  outcome semantics (gap type -> release blocker `fail` or warned finding
  `warn`).
- `crosswalk.json`: framework controls (DORA, EU AI Act, ISO 42001, SOC 2,
  NCSC CAF, NIST AI RMF, OWASP LLM Top 10) mapped to the raucle evidence field
  (`evidence_field`, a dotted path into the assurance packet) and the repo
  artifact that backs it (`basis`). UNSUPPORTED rows state in `unsat_reason`
  why nothing in the current evidence plane satisfies the control. These are
  honest gaps, never padded green.
- `validator.py`: validate(packet, profile) -> PASS/PARTIAL/FAIL with a
  machine-readable diff (every unsatisfied check with expected/actual/note).

## Packet shape coded against

The validator codes against the versioned `agent_assurance_packet` shape
documented in OV-1 of `docs/roadmap/overnight-sprint-backlog.md`:
`schema_version`, `kind`, `agent`, `capability_chain`, `policy_proof_refs`,
`receipt_chain` (`total_count`, `verified_count`, `invalid_or_missing_count`),
`coverage` (`gate_covered_tools`, `unverified_tools`), `governance`
(mapping slots per framework, flat dict or list), `risk_annotations`.
Missing fields degrade to PARTIAL, never silently PASS; a packet naming a
wrong `kind` fails.

## Verdicts

- PASS: every check satisfied.
- PARTIAL: honest gaps only (missing packet evidence, crosswalk PARTIAL rows).
- FAIL: receipt-integrity failure, unverified tools (regulated), a packet
  claiming more than the crosswalk establishes (`tampered_claim`, every
  profile), an unknown status vocabulary, an invented control, or (regulated)
  any absent required framework or UNSUPPORTED required control.

Note: under `regulated` the shipped crosswalk currently tops out at PARTIAL
(DORA Art 5(1), EU AI Act Art 15(1), ISO 42001 A.7.2): a regulated release
today cannot honestly reach PASS. That is the intended, honest boundary until
those controls gain full packet evidence.

The repo's compliance-honest invariant applies: the validator never derives
legal or regulatory compliance from a PASS verdict; it only verifies declared
coverage against documented evidence.

## Use

```bash
.venv/bin/python ops/assurance-profiles/validator.py --packet packet.json --profile regulated
# exit code: 0 PASS / 1 PARTIAL / 2 FAIL / 3 profile-data defect (see stdout JSON)
```

Tests: `tests/assurance/test_profiles_crosswalk.py`.
