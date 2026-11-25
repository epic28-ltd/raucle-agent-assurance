# Independent-vantage bypass and custody adversarial test matrix

Status: implementation baseline reviewed; SEC-010 lease matching hardened in PR branch
Scope: deterministic, synthetic, offline tests over index-plane evidence
Decision record: [ADR 0004](../adr/0004-bypass-detection.md)

This matrix states what the current tests establish. It does not claim universal
prevention or detection of bypass. Detection depends on independent vantage
coverage being configured and available for the tool under review.

## Coverage map

| Tool class | Independent vantage | Current declared coverage | Honest interpretation |
|---|---|---|---|
| `shell` | C: credential lease/custody | Declared in `services/rules/config/rules.yaml` | SEC-010 evaluates custody events for this tool only |
| `shell` and other configured privileged operations | A: tool-side audit + G: gate receipt | Source-specific audit conventions and correlation | SEC-009 identifies discrepancies only when tool-side evidence is available |
| Tools with ambient credentials outside the custody map | A/G only, if audit integration exists | Not covered by SEC-010 | Never describe these tools as lease-custody protected |
| Tools with neither independent audit nor custody events | T may exist, but is agent-controlled | Unobserved | Trace-only telemetry is not an authoritative bypass signal |

## Scenario matrix

| Threat / evidence condition | Vantage inputs | Expected state or rule | Test coverage |
|---|---|---|---|
| Privileged tool-side execution, no correlated gate receipt, beyond grace | A without G | `bypass_suspected`, SEC-009; human review, no intent attribution | `test_bypass_positive_privileged_no_receipt`; SEC-009 positive fixture in `tests/services/test_rules.py` |
| Tool-side execution with a corroborating allow receipt | A + G | Matched; no SEC-009 finding | SEC-009 `negative-privileged-execution-corroborated` |
| Tool-side execution with a corroborating deny receipt | A + G | SEC-004 finding when tool-side outcome is success | SEC-004 `positive-success-after-correlated-deny` |
| Trace-only narrative says a tool call occurred without a receipt | T only | No SEC-009 bypass finding | SEC-009 `negative-trace-only-signal-never-corroborates` |
| No independent tool-side execution record | G or T only | Evidence gap, not proof of non-execution | `test_receipt_only_gap_is_evidence_gap_not_non_execution`; SEC-009 `negative-evidence-gap-is-not-bypass` |
| Receipt arrives inside the reconciliation grace period | A/G incomplete | Pending; no premature bypass finding | `test_pending_when_grace_not_elapsed`; `test_receipt_only_gap_pending_inside_grace` |
| Late-arriving receipt is correlated | A + G | Receipt is corroborated; no SEC-001 missing-receipt finding | SEC-001 `negative-late-arrival-is-corroborated` |
| Duplicate audit or receipt delivery | A/G duplicated | Duplicate state; provenance retained | `test_table_reconciliation_states` cases `duplicate-receipt-deliveries` and `duplicate-candidate-deliveries` |
| Multiple plausible receipts match one audit event | A + G ambiguous | Ambiguous, low confidence, human review | `test_ambiguous_two_binding_tokens_on_one_candidate`; reconciliation table `ambiguous-degraded` |
| Actor identity differs between audit event and receipt | A + G identity mismatch | No degraded match; privileged audit candidate remains `bypass_suspected`, receipt remains `receipt_only_gap` | `test_actor_mismatch_never_degrades_into_a_receipt_match` |
| Clock skew at either reconciliation window edge | A + G time-window match | Inclusive ±120s boundary matches; ±121s does not | `test_time_window_boundaries_are_symmetric` |
| Privileged invocation has no receipt after grace | G correlation | SEC-001 high-confidence finding | SEC-001 `positive-receipt-missing-privileged` |
| Privileged invocation is still pending | G correlation | No SEC-001 finding before grace closes | `test_pending_when_grace_not_elapsed` |
| Credential use has no matching prior lease | C | SEC-010 critical/high-confidence custody discrepancy | SEC-010 `positive-credential-use-no-lease` |
| Lease belongs to another agent or tool | C | SEC-010 finding; unrelated lease cannot cover use | `test_sec010_requires_same_prior_non_revoked_lease` |
| Use specifies a different lease or release identifier | C | SEC-010 finding | `test_sec010_requires_same_prior_non_revoked_lease` |
| Lease is issued after the credential use | C | SEC-010 finding | `test_sec010_requires_same_prior_non_revoked_lease` |
| Lease is revoked before use | C | SEC-010 finding | `test_sec010_requires_same_prior_non_revoked_lease` |
| Lease is revoked after use | C | Earlier use remains covered | `test_sec010_requires_same_prior_non_revoked_lease` |
| Tool is outside the custody coverage map | C | SEC-010 does not evaluate it | SEC-010 `negative-tool-not-in-custody-coverage-map` |
| Agent uses ambient credentials outside custody deployment | A/G only | No SEC-010 protection claim; audit reconciliation only | Coverage-map negative boundary above |

## SEC-010 matching contract

A `lease_issued` event covers a `use` only when:
1. The credential identifiers match.
2. Issuance time is less than or equal to use time.
3. Every identity, tool, release and lease identifier present on the use
   event matches the issuance event. Missing issuance-side identity does not
   satisfy a known use-side identity.
4. No matching `lease_revoked` event for that lease and credential occurred
   at or before the use.

The current event model has no lease-expiry timestamp. The rule therefore
does not infer expiry. A deployment that requires expiry enforcement must
emit explicit revocation events or extend the event contract with an
authoritative expiry field. This boundary must remain visible in deployment
assurance documentation.

## Test execution and evidence limits

- All fixtures are synthetic, deterministic and offline; they must not contain
  real customer identifiers, tokens, credentials or production audit events.
- Tests validate the rules and reconciliation logic, not the completeness or
  authenticity of a deployed cloud audit feed.
- A passing test does not prove that every execution path emits independent
  audit/custody evidence.
- Deployment owners must provide a per-tool coverage map and prove audit
  source configuration, identity binding, delivery latency and failure alerts.
- Independent penetration testing is still required for a production security
  assurance claim.
