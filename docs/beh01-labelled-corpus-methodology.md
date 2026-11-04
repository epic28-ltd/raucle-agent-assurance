# BEH-01 — Labelled corpus methodology: behavioural baselines with FP measurement

Status: shipped with BEH-01 (behavioural baseline engine, `services/rules/src/oaa_rules/baseline.py`).

## What a "labelled window" is

A **labelled run** (`oaa_rules.LabelledRun`) is one agent session bounded
in time, carrying:

- `run_id` — the session identity (corpus case id today; a real run id later),
- `label` — ground truth: `benign` or a named hostile class
  (`bypass`, `prompt_injection`, ...). Labels travel OUTSIDE the events and
  are never consulted by any rule's arithmetic — they exist for measurement
  and documentation only,
- `events` — the same index-plane records the SEC rules consume
  (correlation, tool_audit, verification, ingest), always `synthetic=True`
  in the corpus,
- a window start/end.

A **baseline** (`oaa_rules.build_baseline`) is built from a set of labelled
runs: per `(agent_id, release, tool)` key it holds runs seen, calls per run,
steps per run, denial ratio, the observed hour-of-day span, and a
`latency_p95_ms` placeholder (index rows carry no latency today; the field
exists so the persisted schema keeps its shape when latency lands). The
baseline is content-addressed (`baseline-<sha256(label,tools)[:16]>.json`)
under `baselines/` with a `registry.json`; identical windows re-save to the
same file.

## How benign / bypass sessions get labelled later (real deployments)

1. **Corroborate first, label second.** A session is labelled `benign` only
   when the existing evidence plane closes it: correlated receipts match the
   tool-side records, verification is valid (ADR-0001) and no SEC rule fired
   terminal findings for the trace set. A session is labelled `bypass` when
   SEC-004/SEC-009-grade corroboration shows tool-side success without a
   gate receipt. Everything else stays **unlabelled** and is excluded from
   the window — an opinion is not a label.
2. **Human adjudication lands on the findings board.** Triage decisions in
   the investigation UI (confirm / suppress-with-reason) are the
   adjudication record; a batch export of resolved traces with their triage
   outcome becomes a labelled run batch, one batch per release window.
3. **Replay is deterministic.** Labelling never changes rule arithmetic:
   the same events replayed against the same baseline produce byte-stable
   findings. Labels only select which runs build the baseline and which
   count as false positives.
4. **Baselines are versioned and labelled.** A baseline stores its label
   set and build window; replacing a baseline is a versioned registry
   change, never an in-place edit.

## False-positive measurement (REQUIRED before any BEH rule ships)

`measure_false_positives(baseline, runs, config)` runs every BEH rule
per-run against the labelled corpus and reports:

| field | meaning |
| --- | --- |
| `benign_runs` / `non_benign_runs` | labelled window sizes (corpus today: 40 / 60) |
| `fp_count` | **benign** cases flagged by any BEH rule |
| `tp_count` | non-benign cases flagged |
| `precision` | tp / (tp + fp) over flagged cases |
| `fp_bound` | documented hard bound: ceil(15% of benign cases) |

**Documented bound: `fp_count <= ceil(0.15 * benign_runs) == 6` for the
corpus.** The gate is pinned in `tests/eval/test_beh01_fp.py`; a benign FP
above the bound fails the suite. Measured today: `fp_count == 0`
(`fp_cases: []`), `tp_count == 2` (MULTI-090, MULTI-095 — pooled multi-step
volume exceeds the benign baseline), `precision == 1.0`.

### Pooling caveat (methodological note)

Every corpus case gets a distinct agent id, so per-agent keys would make the
drift rules vacuously silent. The measurement harness pools benign cases
onto one agent key (`agent-pooled-benign`) **before** building the baseline
and evaluates every case with the same pooling — release and tool survive
pooling so BEH-D's SEC-006 reuse keeps its config-driven semantics. This is
the pooled-proxy design the first real deployment replaces with genuine
per-agent baselines.

## Rule semantics (all ADVISORY)

- **BEH-A volume-step change**: steps/run in the window > baseline median +
  3x MAD (robust) or mean + 3 sigma (parametric), whichever fires first; a
  degenerate (zero-MAD) baseline falls back to a one-step MAD floor.
  Needs >= 3 baseline runs per key; other agents stay silent.
- **BEH-B denial-ratio shift**: window denial ratio > 2x the baseline ratio
  with >= 3 window calls and >= 1 deny; a zero-denial baseline shifts on any
  qualifying denial (severity medium there, low otherwise).
- **BEH-C late-hour volume**: >= 2 tool events outside the labelled
  baseline's observed hour-of-day span (UTC).
- **BEH-D new tool off baseline**: SEC-006 reused — the acknowledged
  release registry decision stays in `rules.yaml` (config change, not code);
  BEH-D re-reports it as an advisory behavioural drift, never re-firing the
  SEC-006 pipeline finding.

BEH rules deliberately do NOT join `ALL_RULES`/`run_rules`: they require a
built baseline object, and the SEC corpus expectations pin the SEC pipeline
unchanged. Call `run_beh_rules(baseline, runs, config)` at the point where a
baseline window is available.