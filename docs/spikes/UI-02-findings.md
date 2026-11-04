# UI-02 findings — investigation UI rebuild

Story: UI-02, rebuild of the investigation SPA as a customer-grade product.
Status: complete, tests green, ruff clean. Nothing committed to git.

## What shipped

- `services/investigation-ui/static/index.html` — UI-02 single-page app,
  rewritten from scratch on the same discipline as UI-01: all model/tool/
  index content rendered via `textContent` only, no `innerHTML`, no
  `document.write`, no external fetches (threat model T5 unchanged).
- `services/investigation-ui/static/legacy.html` — the old UI-01 SPA,
  moved verbatim, still reachable at `/legacy.html`. `/` now serves UI-02.
  All v1 server-rendered views (`/view/*`) and all v1 API endpoints
  unchanged.
- `GET /api/dashboard` — simple aggregate: three traffic-light counters
  (`healthy`, `at_risk`, `needs_investigation`), verification and
  correlation distributions, finding counts, run count. No
  re-verification; index-plane only.
- New tests in `tests/test_service.py`: index served at `/`, legacy at
  `/legacy.html`, no unsafe sinks, legend tokens present, guidance map
  covers all 7 verification states + 8 correlation states + SEC-001..011,
  and dashboard counters reconcile with the distributions.

## Semantics notes (decisions worth knowing)

- Bucket ordering is: needs-investigation first (invalid,
  unsupported_schema, receipt_missing), then healthy (valid+matched,
  not_applicable), everything else at-risk (unknown_key, pending,
  unavailable, ambiguous, duplicate, late_arrival, matched_degraded,
  trace_missing, pending correlation). `ambiguous` is not in the
  story's at-risk list explicitly but is un-proven, so it lands there.
- The needs-investigation counter counts flagged privileged spans PLUS
  active (unsuppressed) findings. This makes the counter disagree with
  the verification-distribution total by the number of active findings
  (1 in the demo: SEC-002). The test documents this deliberately.
- Colour map defined once in JS (`VERIF_CLASS`, `CORR_CLASS`) and once
  in CSS custom properties; every chip/timeline node/strip segment
  derives from those tokens. `not_applicable` is grey (structurally
  exempt). The legend bar is static and always visible.

## Guidance copy

- Static `G` map in the SPA with four fields per key: What you are
  looking at / What this means / Could be fine because / Suggested
  actions (numbered, imperative, no intent attribution, per ADR-0004).
- All 7 verification states, 8 correlation states (including
  matched_degraded and trace_missing, which the demo data cannot
  produce today — copy is written defensively for them), and rules
  SEC-001..011 are covered. Copy honest: unknown stays unknown;
  receipt_missing does not claim bypass, it states what must be
  excluded.

## Bugs caught during the build (lessons)

1. The evidence panel initially did `side.replaceChildren(panel)` in its
   async callback, silently wiping the guidance panels appended
   synchronously earlier. Diagnosis took a while because the symptom was
   intermittent-looking (only visible when the auto-selected span had a
   fetch result). Fixed by appending, never replacing, the side dock.
2. `route()` used to re-parse `location.hash` inside the run-view
   checkbox handler; replaced with a direct closure `runId` reference
   before it shipped broken.
3. Browser-cache-free reload requires busting the path (adding `?bust=N`
   in front of the hash), since hash-only navigation never refetches the
   document. Cost several confusing "did my edit ship?" probes.

## Verification performed

- pytest (service tests incl. 6 new UI-02 tests): 16 passed.
- ruff check (src + tests): clean.
- Live: `uvicorn` on 3411 from `services/investigation-ui/nohup.out`
  log; 3410 still on the old build. Checked in a real browser:
  counters 2/7/3 match `/api/dashboard`; counter click filters;
  distribution strips render; trace timeline colour-codes; guidance
  panels dock right with the four headings; Verify offline returns the
  verifier JSON; suppressed-findings toggle adds SEC-001; state chip
  filtering produces the explicit empty state; `/legacy.html` renders
  the old UI; hostile attribute values render as literal text only.

## Known gaps

- Layout untested below 1200px width (story scoped >1200px); the two
  column dock is `position: sticky`, no jank observed at 1280px.
- Overview "filtered items" list fetches every run detail on each
  render; fine for demo volume, would want an aggregate endpoint with
  per-span rows before real data.
- SEC-004/006/008/009/010/011 never fire in the demo fixture, so their
  guidance copy is exercised only by the key-coverage test, not by
  click-through.