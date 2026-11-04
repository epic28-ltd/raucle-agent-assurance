# RULE-01 findings — deterministic security rules (SEC-001..011)

Date: 2026-11-04. Ticket: RULE-01 (SEC-001..008) + ADR-0004 additions
(SEC-009..011). Code: `services/rules/src/oaa_rules/core.py`; config v1:
`services/rules/config/rules.yaml` (schema `schemas/rules-config.schema.json`).

## Design invariants (enforced in code, tested)

- Index-plane inputs only: correlation results (ADR-0002), verification
  results (ADR-0001), tool-side audit records (vantage A), custody/lease
  events (vantage C), receipt *index rows* (hash + decision — never canonical
  receipt bytes).
- SEC-009 never consumes trace-only signals: an absent/extra trace record is
  never a bypass signal. Corroboration for a privileged tool-audit event
  comes exclusively from a correlated receipt in a receipt-exists state
  (`matched | duplicate | ambiguous | late_arrival`). Test
  `negative-trace-only-signal-never-corroborates` pins this.
- Findings state discrepancy + confidence class, never intent
  (`bypass_suspected` wording per ADR-0004).
- Suppression retains, never drops: a suppressed finding keeps every field
  and carries `suppression_reason` (documented in versioned config).
  Narrow matching: each named field must equal. NOTE: matching against the
  primary evidenced event requires that event to carry a `ref` — correlation
  record keys on `trace_id` are matched through the finding's evidence ref
  only.
- SEC-008 reports pattern NAMES + record refs; matched content is never
  written to any finding field (`test_no_finding_ever_carries_raw_matched_content`).
- `evidence_gap` (nothing observed on any independent vantage) is never a
  finding. In-grace `pending` correlation records are never evaluated.

## Rule → input mapping

| ID | Fires when (deterministic condition) | Inputs (index plane) | Sev/Conf | Key config |
|---|---|---|---|---|
| SEC-001 | correlation `receipt_missing` for a privileged tool | correlation records + privileged registry | high/high | `privileged_tools.registry`, `grace_seconds` |
| SEC-002 | verification state `invalid` (high) or `unsupported_schema` (medium) | verification results | high/med, high/high | `verification_failure_states` |
| SEC-003 | deny/total over threshold in a sliding window per application (first qualifying window per app) | tool-audit decisions | high/medium | `deny_rate.{threshold,window_seconds,min_samples}` |
| SEC-004 | tool-audit `success` on a trace whose correlated receipt decision is `deny` | tool-audit + correlated receipt index rows | critical/high | — |
| SEC-005 | calls per (agent, tool) exceed `max_calls` within window | tool-audit | medium/medium | `tool_cycle.{max_calls,window_seconds}` |
| SEC-006 | privileged tool observed for a release absent from its acknowledged baseline | tool-audit + versioned baseline | high/medium | `tool_baseline` (baseline change = config edit) |
| SEC-007 | unavailable ingest/verification ratio ≥ threshold over ≥ min_events (fail-visible, ADR-0001) | ingest + verification results | high/medium | `backlog.{unavailable_ratio_threshold,min_events}` |
| SEC-008 | named config pattern matches telemetry index content; presence only, payload redacted | telemetry index text | critical/high | `patterns` |
| SEC-009 | `bypass_suspected`: privileged tool-side execution with no corroborating receipt beyond grace; unkeyed execution = medium confidence | tool-audit (A) reconciled against correlated receipts (G); **never T** | critical/high-or-medium | `privileged_tools` |
| SEC-010 | credential `use` with no `lease_issued` for that credential, on a custody-covered tool (C vantage; silence when no custody data) | custody events + coverage map | critical/high | `custody_covered_tools` |
| SEC-011 | `producer_id` change between consecutive chain steps for one agent | identity/ingest records | high/medium | — |

## False-positive considerations

- **SEC-001/SEC-009 clock-skew and batching**: tool-side audit may land after
  the correlation grace (ADR-0004 §Consequences). Mitigation: grace config is
  explicit and must be ≥ the deployment correlation grace; documented
  suppressions retain findings. `late_arrival` never fires SEC-001 or
  suppresses SEC-009 (the receipt exists).
- **SEC-009 unkeyed executions** (no trace key) are medium confidence — they
  cannot be correlated at all; treat as instrumentation debt plus review.
  Instrumentation gaps (audit missing entirely) stay silent: an evidence gap
  is a coverage state, not a bypass signal.
- **SEC-003**: bursty-but-legitimate retry loops can look like denial waves;
  `min_samples` + `break` at first qualifying window keeps volume bounded and
  windows human-readable. Tune threshold per application, not globally.
- **SEC-005**: long-running batch jobs legitimately exceed call bounds —
  bound per (agent, tool) with per-agent overrides in config.
- **SEC-007**: fail-visible by design means planned maintenance can trip it;
  window it via a documented suppression with retention.
- **SEC-008**: patterns over telemetry can false-positive on code/text that
  quotes credential *shapes* (docs, tests in traces). Finding names the
  pattern, the human decision remains reviewer-side; payload is redacted so
  the finding itself cannot leak the secret.
- **SEC-010**: only scoped to the custody coverage map — deliberately silent
  for ambient-credential tools (ADR-0004 honest limit).
- **SEC-011**: legitimate credential rotation with producer re-auth shows a
  new producer with an authenticated step — only *unchained* changes (no
  authentication context change) fire; if rotation-with-reauth needs
  exemption, that enters config as a documented suppression.

## Coverage statement (rules vs vantage points)

Per ADR-0004 suite-claim wording: Agent Trust proves what was allowed to run
on gated paths; Agent Assurance detects what ran outside them, **to the
extent independent vantage points exist**.

| Vantage | Used by | Coverage claim |
|---|---|---|
| G: gate receipts (index rows) | SEC-001/002/004/007 | strong: signed + offline-verifiable |
| A: tool-side audit | SEC-003/004/005/006/009 | only where tool hosts are agent-untrusted; declared per deployment |
| C: custody/leases | SEC-010/011 | strong ONLY for tools in the custody coverage map |
| T: trace telemetry | SEC-008 (content scan, index only) | never used for bypass attribution; narrative only |

Coverage is declared per tool, never implied. Trace-only records can raise
SEC-008 (content) but can never suppress or raise SEC-009.

## Verification

`pytest` 72 passed + 1 skipped (baseline 22P+1S intact; +49 rule-engine and
config tests, all raucle-free, table-driven positive/negative/suppressed
covers every rule), `ruff format --check` + `ruff check` clean repo-wide.