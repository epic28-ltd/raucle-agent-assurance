# RED-INTEGRATION findings — Raucle Agent Red findings ingest into Assurance

## What landed

The Red product gets a real ingestion contract into the Assurance
investigation UI: at the end of every red run it can POST its findings
JSONL to the existing Assurance process and the findings appear on the
findings board, counted by the shared counting module, with a Red source
tag and per-rule guidance. Nothing external is called; the intake is
local-only and sidecar-persisted.

## Ingestion contract (POST /api/findings/ingest)

- Wire body (all three accepted, exactly what `corpora/findings.jsonl`
  contains):
  1. JSON array of finding objects,
  2. `{"findings": [...]}` envelope,
  3. raw JSONL text (one finding object per line; blank lines and
     `#` comment lines ignored).
- Per-finding schema (validated, 422 on any violation):
  - `finding_id`: deterministic UUID5 (RFC-4122 variant, version 5).
    Re-posting a run reproduces the same ids, which is what makes
    re-ingestion idempotent.
  - `rule`: `RED-xxx`; `rule_label`, `explanation` (what was observed —
    no intent attribution), `suggested_action`, `suite`: strings.
  - `severity`: `info | low | medium | high | critical`.
  - `confidence`: `low | medium | high`.
  - `evidence_ref`: `{kind, value, sha256}` with sha256 = 64 hex chars.
- Evidence integrity: when `evidence_ref.value` is a local file path that
  exists (e.g. `fixture_store` refs), the file is re-hashed at ingest and
  the digest must match `sha256`, else 422. Non-path refs (audit rows
  where value == the hash itself) are format-checked only.
- Storage: accepted findings merge into `red_findings.json` inside the
  data dir (same sidecar pattern as `triage_state.json`; the canonical
  evidence store is never touched). Idempotent by `finding_id`: a
  re-post replaces same-id entries; the response reports
  `{total, accepted, replaced, new}`.
- New read surfaces: `GET /api/findings/red` (board-shaped red slice +
  by-severity counts) and red rows inside `GET /api/findings/board`.
- Every red board row is source-tagged `red-mvp` (assurance rows carry
  `source: "assurance"`) and carries a `guidance` string: per-rule text
  for the rules the corpora emit today (RED-003/004/006/007/009/011),
  else the generic red fallback (`red_guidance()` in `red_intake.py`) —
  the red rules are not in the assurance static G map, so the guidance
  ships in the payload itself.

## Counting integration (counting.py, still the single source)

- Ingested red findings are folded into the SAME findings loop as the
  assurance findings: `findings.total = assurance findings + red
  ingested` and `open + closed + suppressed == total` still closes over
  the merged list (asserted in code, tested in
  `tests/services/test_red_intake.py`). No double-counting: the counts
  loop is the only place red is counted; the `red` section of
  `/api/counts` (`{ingested, by_severity}`) plus
  `assurance_findings_total` / `red_total` are reported shares, not
  recounters.
- Severity → board risk-lens mapping (red rules have no SEC semantics,
  so the fold is by severity only; documented in `counting.py` and
  `red_intake.py`):
  - critical / high → `needs_investigation` (discrepancy needing an
    investigator decision);
  - medium / low → `unproven`;
  - info → `unproven` (an info finding attests only that a probe ran and
    its detection logic confirmed; that is a resilience claim a human
    has not judged, so it never lands in `coverage_gaps` — a red probe
    is presence evidence, not an absence rule).
  All five severities map (asserted: every ingested row lands in a lens
  bucket), and the board column counts sum to the same total.

## Console Red page (surgical copy edit)

- `services/console/static/index.html` (viewRed): the teaser
  "Coming soon. Wave two of the suite; announcing later." was replaced
  with honest product copy: "Wave 2 in build. The gate fuzzer already
  runs against your policies; every attack it attempts is itself gated
  and receipted."
- New "Ingested red findings" card in the same view: count by severity,
  latest finding (rule, severity, explanation) and a link into the
  Assurance board, fetched live from `/api/findings/red` with the same
  graceful-degradation pattern as the other console cards. Everything
  renders `textContent`-only (asserted in tests); when the Assurance
  add-in is offline the card says so instead of guessing.

## Files

- NEW `services/investigation-ui/src/oaa_investigation_ui/red_intake.py`
  — parser, validator (UUID5 / enums / sha256 integrity), sidecar store,
  board projection, guidance map.
- EDIT `services/investigation-ui/src/oaa_investigation_ui/app.py` —
  `POST /api/findings/ingest`, `GET /api/findings/red`, board merge with
  source chip + guidance.
- EDIT `services/investigation-ui/src/oaa_investigation_ui/counting.py` —
  merged counting loop, severity→lens fold, `red` section, documented
  mapping.
- EDIT `services/console/static/index.html` — viewRed copy + summary
  card only.
- NEW `tests/services/test_red_intake.py` — 9 tests: intake idempotency,
  integrity re-verification (match + mismatch), corpora-shape ingestion
  (real red JSONL end-to-end), rejection cases (non-UUID, UUIDv4,
  bad severity, non-RED rule, missing fields, empty), counting
  coherence (total = assurance + red, partition closes, board columns
  agree with counting), board red-row rendering + guidance fallback,
  console-copy assertions.

## Future Red product behaviour (the deal)

At run end the Red product POSTs its full `findings.jsonl` for the run
to `/api/findings/ingest`. Re-runs are safe (deterministic ids ⇒
idempotent). No filtering, no scoring, no intent attribution happens on
the Assurance side — the board is where a human triages red output next
to assurance findings, under the same counting discipline.

## Known gaps (deliberate, alpha)

- The UI board SPA (static JS) does not yet color a red source chip;
  it renders whatever `/api/findings/board` payloads now carry
  (`source`, `guidance`) — a follow-up static-only edit outside this
  spine.
- The console board link points at the Assurance board page; a
  source-filtered deep link (e.g. `?source=red-mvp` honored by the
  board SPA) is left for the same follow-up.
- Triage of red rows happens on the normal board path
  (finding ids `red-<uuid>`), which works, but the red id namespace is
  not visually distinguished in the SPA yet.

## Verification

- `pytest tests` — 317 passed, 2 skipped (real corpora ingested
  end-to-end in the suite; sha256 integrity re-verified at ingest).
- `ruff check .` — clean.