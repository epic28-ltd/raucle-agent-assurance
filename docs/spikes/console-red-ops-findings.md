# Console red ops and findings (wave 2.5)

## Scope

The console's Red page (viewRed) now drives the separate red runner
process through the console's own proxy endpoints. The SPA still makes
no cross-origin call and the console gained no other outbound target
than the runner origin (127.0.0.1:3415, `RAUCLE_RED_RUNNER_URL`) and
the already-configured Assurance add-in origin.

## Proxy routes added (services/console app.py)

| Route | Forwards to | Notes |
| ----- | ----------- | ----- |
| GET /api/red/targets | GET :3415 /targets | demo gateway + named gates with endpoint / policy digest |
| POST /api/red/run | POST :3415 /run | preset must be quick or deep; target non-empty; runner stays arbiter |
| GET /api/red/status | GET :3415 /status | polled every 2s by the SPA while a run is watched |
| GET /api/red/results | GET :3415 /results | finding rows + receipts counter |
| POST /api/red/stop | POST :3415 /stop | operator abort; /status still governs the shown verdict |
| POST /api/assurance/findings/ingest | POST assurance /api/findings/ingest | 422 pass-through; 503 offline |

Every proxy degrades explicitly: nothing on the runner port yields a 503
with `error: red runner offline`, and the SPA renders that as an honest
state line. A runner-side rejection passes through with its own status.

## Console UX (textContent only, nothing autostarts)

- Run a test card: target selector (demo gateway, plus runner-registered
  gates), preset radios (Quick pass / Deep sweep), a scoped preview of
  exactly what a start means (suites, attempt budget, loopback-only,
  synthetic-data and receipts dogfooding lines), Start and Stop.
  Controls disable while a run is in flight.
- Live results card: state chip with semantic tints (idle grey,
  running amber, complete green, aborted red), attempts / allow / deny /
  findings counters, current suite, receipts minted (dogfood tick-up).
  Polling runs every 2s only while watched: the interval is cleared when
  the run ends or is aborted, on tab hide (visibilitychange) and on
  navigation away. Returning re-reads /status and resumes if the runner
  still reports a run in flight. Honesty: the runner keeps running
  while the page is not watching; the page never pretends otherwise.
- Gates for testing card: the runner-reported registry; 'test this gate'
  pre-fills the target selector.
- Ingest findings into Assurance: posts the /results rows to the intake,
  then re-reads the ingested-findings summary. Ingestion is idempotent
  by finding_id (red_intake sidecar merge), so re-ingesting the same run
  replaces rather than duplicates; the UI states this.

## Wire shapes

The runner contract (preset, target, state enum, counters) is kept
loosely parsed with safe fallbacks: the console shows what the runner
reports and renders 'nothing guessed' lines where a field is absent.
Findings rows forwarded to the Assurance intake follow the documented
red schema (deterministic UUID5 finding_id, RED-xxx rule, severity and
confidence enums, sha256 evidence_ref), so validation stays entirely at
the add-in and rejections surface verbatim in the console.

## Not done here

The runner itself (port 3415) is a separate build. Any test expecting a
live runner skips the 2xx branch (offline-only assertions hold).