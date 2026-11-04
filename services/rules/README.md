# services/rules — RULE-01 deterministic security rules engine

License: Apache-2.0.

`oaa_rules` evaluates **SEC-001..SEC-011** over index-plane records only:
correlation results (ADR-0002), verification results (ADR-0001), tool-side
audit records (vantage A), custody/lease events (vantage C), and receipt
*index rows* (hash + decision — never canonical receipt bytes). Bypass rules
never touch trace-only content (ADR-0004).

- `src/oaa_rules/core.py` — `Event` (index-plane record), `Finding`
  (rule_id, rule_version, severity, confidence, evidence_refs, explanation,
  optional `suppression_reason`), `RulesConfig`, eleven rule classes and
  `run_rules()`. All deterministic, table-driven-testable.
- `config/rules.yaml` — versioned config (schema v1): thresholds, default
  privileged-tool registry, release baselines, patterns, custody coverage
  map, documented suppressions. `load_config()` parses it (PyYAML).
- `schemas/rules-config.schema.json` — JSON schema for the YAML.

Findings state the observed discrepancy and a confidence class — never
intent. Suppressed findings are **retained** with `suppression_reason` set.
SEC-008 reports pattern *presence* only; matched content never lands in a
finding. See `docs/spikes/RULE-01-findings.md` for the rule-to-input mapping
and false-positive analysis.