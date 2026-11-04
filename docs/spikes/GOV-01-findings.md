<!-- SPDX-License-Identifier: Apache-2.0 — markdown at repo level, like other spikes -->
# GOV-01 findings: scoped assurance report generator

Story: *Retention and assurance report — limits and unknowns included; no
compliance claim* (plan P1; mitigates threat-model section 16 risk
"Evidence UI exaggerates compliance"). Suite positioning: **sovereign by
construction — signed locally, verified anywhere** — the report therefore
asserts no more in prose than the evidence plane asserts cryptographically,
and says so in a fixed limits section a reviewer cannot miss.

## Outcome

`ops/assurance/generate_report.py` produces one markdown assurance report
from the index plane (see `ops/assurance/example-report.md`, generated from
the UI-01 demo data). Verified by the generator tests (`tests/assurance/`):
all verification-state buckets rendered (including zero-count rows), the
mandatory limits section present, suppressed findings retained with reasons,
tool-side reconciliation explicit when audit events are absent
("not provided — coverage unverified"), no banned claim term anywhere
(scanner + test), deterministic with a pinned clock. Full suite green, ruff
clean.

## Design

One markdown report per queried slice, generated from the index plane only
(`ops/assurance/generate_report.py`), inputs in the read-only demo-data
store layout; UI-01, COR-01, RULE-01 and ADR-0001 semantics are reused, not
re-derived:

- **Verification state distribution** (ADR-0001): all seven states as table
  rows — `valid, invalid, unknown_key, unsupported_schema, pending,
  unavailable, not_applicable` — zero-count rows included. Explicit unknown
  states are their own buckets; nothing silently degrades to blank.
- **Correlation state distribution** (ADR-0002): `matched, receipt_missing,
  trace_missing, ambiguous, late_arrival, duplicate` plus the in-grace
  `pending` open-record count, which is never presented as a result.
- **Findings** (RULE-01): active findings table, and suppressed findings
  RETAINED with their documented reasons inline — the reviewer sees the
  suppression and its justification where it matters.
- **Tool-side reconciliation summary**: rendered only when tool-side audit
  event rows are provided; otherwise the fixed sentence "Tool-side audit
  events: **not provided — coverage unverified**." (receipt-side evidence
  alone cannot establish what executed tool-side; the gap is stated, not
  hidden).
- **Mandatory limits section** (fixed, generated, never hand-edited):
  scope statement (gated paths only), per-tool coverage from the custody
  coverage map (`ops/assurance/config/coverage.yaml`, default `unverified`),
  the verification trust model in one line, the explicit no-legal-clause,
  and a reference to the unknowns/unverifiable-ranges section.

No-claim guarantee is structural, not editorial: `generate_report` ends with
`assert_no_compliance_claims(text)` — a scanner over the rendered output that
rejects any line where a banned claim stem (`complian`, `certif`, `approv`,
`accredit`, `attest`, `warrant`) appears outside an explicit negation. A
positive-context phrase like "the run is compliant with policy" fails the
generator; the required disclaimer ("a receipt or this report does not
establish legal or regulatory compliance of any kind") passes because it is
a negation. A test re-scans the output independently and also asserts the
disclaimer is present, so the report cannot drift into a compliance claim
without the suite failing.

Determinism: the generation clock is injectable (`--clock` ISO-8601); with
it pinned, two runs are byte-identical (tested with a mixed-state fixture).

## Retention

What the report consumer must know, and what the index must carry, if
evidence is deleted per its lifecycle:

- The report is a **point-in-time view over retained evidence**. If a
  retention window has expired and evidence was deleted, receipts outside
  the remaining range are unverifiable *by construction* — the report's
  unknowns section says so in a standing bullet, not a footnote.
- What the evidence index must provide for a retention-aware report:
  1. Per-sink ingestion coverage ranges (`first_seen`/`last_seen` per
     provenance, as the COR-01 index rows already carry), so the unknowns
     section can state which time ranges are simply absent from the store.
  2. A retention-status marker per evidence range: `retained` |
     `scheduled_for_deletion` | `deleted`. Today's verification index has
     no such field; a deletion process would have to leave a tombstone row
     (`status: deleted_at:<ts>`) because an absent row is indistinguishable
     from never-ingested.
  3. The ingest availability events (the `unavailable` verification rows)
     must be retained even when the receipts they described are deleted —
     they are the audit trail of the coverage gap itself (fail-visible,
     ADR-0001 consequences).
- Deletion authority and lifecycle: evidence deletion belongs to the raucle
  **records-lifecycle** configuration (see the raucle records-lifecycle
  settings for retention windows and the deletion request/grant flow). This
  companion never deletes evidence on its own initiative; it only marks and
  reports. The index-side retention config therefore needs: (a) a tombstone
  schema addition, (b) the raucle records-lifecycle window as the authority
  for when a range may be tombstoned, and (c) an explicit rule that
  tombstoned ranges are surfaced in every subsequent GOV-01 report's
  unknowns section.

## Integration points

- **Investigation UI panel (now):** the report maps 1:1 onto the existing
  UI-01 surfaces — verification buckets, correlation buckets, findings with
  retained suppressions. A UI export affordance can call the same
  `generate_report()` function the CLI uses, so what a reviewer exports is
  byte-identical to what the test suite asserts. The mandatory-limits
  section should render above the fold, not in a collapsible footer.
- **SIEM event kind (later):** a new index-plane event kind
  `assurance_report` (candidate addition to the RULE-01 `EVENT_KINDS` set)
  publishing the report's digest (sha256 of the rendered markdown), its
  scoped range, and its counts — so a SIEM can alert on *changes* in the
  distribution of unknown states between successive reports, not on report
  content. The report document itself stays in the operator's artefact
  store, never in the SIEM.
- **GOV-02 (candidate follow-up):** the retention tombstone schema and the
  `assurance_report` event kind are the two index-plane prerequisites this
  story identifies but does not implement.