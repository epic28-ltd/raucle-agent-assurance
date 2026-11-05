# SPDX-License-Identifier: Apache-2.0

# oaa_prebind — Prebind Assurance indicators (OV-12)

Derives CAGE-1 (arXiv:2607.03510) prebind lifecycle states from gate receipt
evidence the repo already produces: the synthetic receipt index, committed run
spans, and red findings.

## Honest derivation contract

- `admitted`: receipt decision `allow` on provenance-receipt/v1.
- `refused`: receipt decision `deny`.
- `unresolved`: documented extension — no decision recorded, legacy schema,
  duplicate receipt hash, ambiguous trace, or missing receipt for an observed
  privileged decision. Never promoted to a fabricated consequence state.
- `held`, `narrowed`, `escalated`, `quarantined`, `no_bind`: reported as an
  explicit honest zero until the gate itself writes that vocabulary into
  receipts. The zero is annotated, not silent.

Red findings that evidence enforcement weaknesses (RED-011, RED-013, RED-017)
are surfaced as `enforcement_weaknesses`; verified PASS findings
(RED-004, RED-009, RED-015, RED-019) are labelled boundary-held evidence in
annotations without inflating any state counter.

All derivation is deterministic and offline-verifiable from committed
fixtures (`services/investigation-ui/demo_data/`). Tests live in
`tests/prebind/`.
