# SPDX-License-Identifier: Apache-2.0
<!-- SPDX-License-Identifier: Apache-2.0 -->

# EVAL-01 findings — synthetic regression corpus + offline harness

Status: **implemented** (P0). Deliverables: `tests/eval/` (generator, corpus,
harness, pytest runner) + CI wiring in `.github/workflows/ci.yml`.

## What was built

- `tests/eval/corpus/corpus.json` — 100 versioned synthetic cases stamped
  `corpus_version: eval-01-v1`, seeded (`seed: 20261104`). Deterministic
  generation: no wall clock, no hash-order dependence; two generations are
  byte-identical (asserted in `test_corpus.py`).
- `tests/eval/generate_corpus.py` — the seeded generator. Expectations are
  **designed per scenario template from rule semantics, never computed by
  running the engine**, so a regression shows as a corpus failure, not a
  silent expectation update.
- `tests/eval/run_corpus.py` — offline replay: builds synthetic receipt
  INDEX rows (fake, case-derived hashes, `synthetic: true` markers) and
  trace-side records per mocked step, runs `oaa_correlation.reconcile` at
  `at=None` (fully terminal), then runs `oaa_rules` SEC-001..011 with the
  SHIPPED versioned config (`services/rules/config/rules.yaml`), asserting
  correlation-state multiset + SEC finding set (with suppression-retention
  checks). Pure function of the corpus + config; no network, no model calls,
  no secrets, no canonical receipt bytes. Writes `tests/eval/results.json`.
- `tests/eval/test_corpus.py` — schema tests, exact-class-table test,
  determinism tests (in-process + subprocess), and 100 parametrized
  per-case replay assertions.

## Case schema

`case_id, scenario_class, description, agent_id, application, steps[]
{tool, trace_id, gate (expected allow/deny/none), outcome, correlation
(expected ADR-0002 state), emit_tool_audit, privileged, release_id},
extra_index_events[] {kind ∈ verification|ingest|custody|identity,
offset_minutes, state?, content?, credential_id?, action?, chain_seq?,
producer_id?, receipt_hash?, secret_marker?}, expected {rules[{rule_id,
suppressed}], correlation{trace_id: state}, pending}, metadata
{generated_by, seed, base_time_utc, step_gap_seconds, synthetic},
secrets_markers[] (sensitive_data only, all marked synthetic).`

## Class table (exactly the plan §10 mix)

| class | count | templates × instances | what it pins |
|---|---|---|---|
| benign | 40 | 8 × 5 | gate holds, thresholds stay silent, duplicate/late/trace-missing quiet, custody-lease coverage satisfied, unprivileged receipt_missing silent |
| out_of_scope | 20 | 5 × 4 | non-registry tools, non-covered custody tools, `unknown_key` verification, sub-threshold backlog are SILENT by design (coverage gap ≠ result) |
| prompt_injection | 15 | 5 × 3 | judged by BEHAVIOUR: gate held (silent), deny-rate spike (SEC-003), ambiguous retry receipts (silent), exfil success-after-deny (SEC-004) |
| infra_failure | 10 | 5 × 2 | receipt-lost invocation (SEC-001), gate-not-deployed bypass (SEC-001+SEC-009), invalid verification (SEC-002), ingest storm (SEC-007), trace-missing stray receipt (NEVER a bypass signal — ADR-0004) |
| multi_step | 10 | 5 × 2 | retry loop over cycle bound (SEC-005), suppressed-but-retained variant, duplicate collapse, hand-off identity change (SEC-011), baseline drift (SEC-006) |
| sensitive_data | 5 | 5 × 1 | fake pattern-matching MARKERS only; SEC-008 presence-only (payload redacted by design), SEC-010 custody violation |

## Rule ↔ class coverage (from expected finding sets; per-rule case counts in
`tests/eval/results.json` → `per_rule`)

- SEC-001: infra_failure (incl. suppression-retention variant)
- SEC-002: infra_failure
- SEC-003: prompt_injection
- SEC-004: prompt_injection (exfil after deny)
- SEC-005: multi_step (incl. suppressed retained variant)
- SEC-006: multi_step (baseline drift)
- SEC-007: infra_failure (fail-visible backlog)
- SEC-008: sensitive_data (4 marker kinds + combined case)
- SEC-009: infra_failure (gate not deployed; trace-missing variants assert
  the negative: trace-only absence is never a bypass signal)
- SEC-010: sensitive_data (+ benign lease-covered negative; out_of_scope
  asserts custody-map silence)
- SEC-011: multi_step (mid-chain producer change)

All 11 rules exercised; the full harness replays green (100/100) against the
shipped config with the CI pytest matrix.

## Harness semantics pinned by the corpus

- A step with `gate: none` must correlate `receipt_missing` (no receipt was
  produced); `emit_tool_audit: false` models a tool that never executed —
  that combination isolates SEC-001 without SEC-009's tool-side signal.
- Correlation `trace_missing` is asserted SILENT at the rules layer
  (ADR-0004 Decision 1 anti-pattern guard).
- Every finding is re-checked to carry no synthetic payload (presence only,
  PRIV-01).

## Gaps / deliberately excluded

- **Online evaluation is out of scope**: this corpus is offline
  reconstruction only; live evaluation (real gate receipts against real
  runs) is future story work.
- **LLM-judge evaluators deliberately excluded** (plan non-goal for P0):
  behavioural grading here is deterministic assertions where ground truth
  exists. LLM-judged behaviour (e.g. refusal quality of agent responses to
  injection) needs an evaluation model — a separate, model-dependent story.
- **Behavioural baselines (BEH-01) later**: per-agent behaviour baselining
  is not attempted here; the corpus contains the raw benign multi-step
  shapes that BEH-01 can build on.
- Injection payloads are single-line behaviour drivers; no multi-turn
  conversation reconstruction yet (needs a trace-level replay format that
  does not yet exist in the index plane).
- Ambiguous-receipt resolution paths are asserted noisy-but-silent; a
  human-review workflow story can reuse INJECTION-{..}c cases.
- Suppressions covered for SEC-001/SEC-005 (shipped config examples);
  other suppressions have no corpus cases until config gains entries.