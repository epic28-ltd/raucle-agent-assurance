<!-- SPDX-License-Identifier: Apache-2.0 -->
# QUAL-01 findings — optional quality scoring

Module: `services/quality` (`oaa-quality`, 0.0.1.dev0, Apache-2.0).
Tests: `tests/services/test_quality.py` (35 tests). Demo:
`services/quality/demo/demo_qual01.py` → `demo_output.json`.

## What was built

- **`src/oaa_quality/rubric.py`** — versioned rubric schema. A rubric YAML
  (`rubrics/qual-v1.yaml`) declares `rubric_id`, `rubric_version`, weighted
  `criteria` (id/weight/description, weights must sum to 1.0, ids unique), a
  positive `applicable_to.scenario_classes` allow-list, and an
  `uncertainty` policy (`min_sample_size` int + prose `abstain_rule`).
  Loading (`load_rubric`, PyYAML) is read-only validation; nothing is
  defaulted or silently renormalised. The runtime package is stdlib-only;
  the YAML import is deliberately lazy (test/demo loading surface).
- **`src/oaa_quality/evaluator.py`** — deterministic reference evaluator.
  Rule-based heuristics only (coverage/hygiene fractions over structured
  records); no LLM call anywhere. `QualityScore` = `{rubric_id,
  rubric_version, score 0-100 | None, criteria_results [{criterion_id,
  score, reason}...], uncertainty low/medium/high, applicability
  applied|abstained:<reason>, reviewer_status="unreviewed", evaluated_ref,
  evaluated_at (caller-injected clock)}`. Abstention rules (returning
  `score=None`, uncertainty `high`, applicability `abstained:<reason>`):
  1. scenario class not in the rubric allow-list (default-deny);
  2. no workflow records in the input;
  3. a criterion has no registered heuristic (never guessed);
  4. a criterion's required data is missing (e.g. no `declared_scope` →
     `scope_compliance` cannot run);
  5. rubric `abstain_rule = abstain_score_if_sample_below_min` with `n <
     min_sample_size` (policy knobs are exercised, not decorative).
  Uncertainty bands: `low` at n ≥ 2×min_sample_size, `medium` at
  n ≥ min_sample_size, else `high`. Heuristics wired only in the
  `HEURISTICS` registry keyed by criterion id.
- **`src/oaa_quality/attach.py`** — attachment is *callback style*, matching
  the sink interface pattern used by the other services: `attach_to_span`
  sets duck-typed `span.set_attribute(f"oaa.quality.*")` attributes;
  `attach_to_callback` hands the rendered attribute dict to a caller-supplied
  sink. `to_score_api_body` renders the JSON body for a (proposed,
  not-yet-built) investigation-ui score API. **Documented, not wired**: the
  console is concurrently under construction, and attaching is the
  caller's choice — this module neither sends anything nor enforces.
- **Demo** — two-workflow case derived read-only from the EVAL-01 synthetic
  corpus (case `MULTI-086`, split into `wf-A`/`wf-B`): applied score 100,
  uncertainty medium (n=2), plus a `sensitive_data` case showing abstention
  at the allow-list. Output written to `demo_output.json`; only that file
  is written.
- **Tests** — rubric schema validation (7 malformed-rubric mutations), all
  five abstain rules, weighted scoring math and truncation, determinism
  (identical scores across runs), injected-clock respect, span/callback
  attachment, score-API JSON round-trip, and the guard tests below.

## Guard (no tools / no secrets / no network)

Static + runtime, over `evaluator.py` + `attach.py`:
- AST scan: no imports of socket/urllib/requests/httpx/http.client/ssl/
  subprocess/multiprocessing/yaml/...; no import roots beyond
  `__future__, datetime, dataclasses, typing, oaa_quality`.
- AST scan: no calls to `eval/exec/compile/__import__/open/popen/system`,
  no `.environ`, no `.open`/`.system` attribute access.
- Regex scan: no secret-shaped string literals (`password|secret|api_key|
  token = "..."`).
- Runtime: identical score produced with `os.environ` scrubbed and cwd
  changed to a tmp dir — the evaluator literally never touches env or
  filesystem. Clock is always injected.

## Why advisory-only

Evaluator outputs are opinions about quality, produced from a rubric a human
chose, over data of unknown provenance. Until there is an agreement
measurement against human review, there is no calibration — and an
uncalibrated score feeding an enforcement gate (deny, block, release) would
turn a heuristic fraction into an authority. So in the MVP:

- every `QualityScore` is born `reviewer_status="unreviewed"`; the schema
  carries the field so a review workflow can take ownership later;
- attachment is a pure renderer + callback; the sink decides what to do
  (the `oaa.quality.advisory=True` attribute makes the status visible
  in every surface it reaches);
- abstention is a first-class result — "cannot score" is recorded and
  reviewable rather than hidden behind a default number;
- retrieved/observed content is treated as untrusted input: strings are
  only tested for emptiness or set membership; never executed or parsed.

## Gaps / deliberately excluded

- **LLM-judge evaluators are excluded** — no model calls, no prompts, no
  model-dependent scoring in QUAL-01. A future LLM evaluator must arrive as
  a *separate rubric version* with its own uncertainty policy, determinism
  guarantees (temperature 0 + pinned prompt), and a different reviewer
  flow; it must never silently replace the heuristic registry.
- **Agreement measurement not built** — no inter-rater agreement
  (e.g. Cohen's κ / Krippendorff α) between scores and human review, so
  there is no calibration data yet (this is the *when approved* gate for
  any enforcement coupling).
- **Cost caps not built** — an LLM evaluator's per-case cost budget,
  sampling rate and spend ceiling are future policy (also *when approved*).
- **investigation-ui score endpoint is proposed, not built** — the console
  is concurrently under construction (see UI workstreams); only the body
  contract (`to_score_api_body`) exists here, no client is shipped.
- Score persistence/review workflow (replaying scores, ownership flips of
  `reviewer_status`) is out of scope for the MVP.
- Applicability is scenario-class-level only; per-application or
  per-agent applicability overrides are future work.

## Verification

- `pytest`: **285 passed, 2 skipped** suite-wide (35 new quality tests green).
- `ruff check .` and `ruff format --check .`: clean (quality package mirrors
  the repo lint selection).
- `scripts/local-gate.sh --warn`: no findings reference
  `services/quality` or the new tests; the reported findings are the
  pre-existing, documented skips (examples receipt JWS fixtures, CI
  actions, dependency CVEs on the console's UI stack).
- Nothing committed to git (work left as untracked files per instructions).