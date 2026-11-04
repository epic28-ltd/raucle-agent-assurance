# oaa-quality (QUAL-01)

Optional, **advisory-only** quality scoring for agent-assurance cases.

- `src/oaa_quality/rubric.py` — versioned rubric schema (`rubric_id`,
  `rubric_version`, weighted `criteria`, `applicable_to` scenario-class
  allow-list, `uncertainty` policy). Rubric YAML lives in `rubrics/`.
- `src/oaa_quality/evaluator.py` — deterministic reference evaluator
  (string/rule heuristics only; no LLM calls, no tools, no secrets, no
  network). Abstains (`score=None`, `applicability="abstained:<reason>"`)
  instead of guessing. Clock injected by the caller.
- `src/oaa_quality/attach.py` — callback-style attachment of `oaa.quality.*`
  span attributes, or a JSON body for the (proposed) investigation-ui score
  API. Pure renderers; nothing enforces, nothing sends.
- `demo/demo_qual01.py` — demo evaluation of a two-workflow case (read-only
  import; writes only its own output file).

Every `QualityScore` carries `reviewer_status="unreviewed"` at birth: a score
is an opinion awaiting a human, never a verdict. See
`docs/spikes/QUAL-01-findings.md`.