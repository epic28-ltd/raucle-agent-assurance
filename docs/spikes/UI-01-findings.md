# UI-01 findings — Investigate tool calls (trace-to-evidence navigation)

Story: analysts investigate agent tool calls — trace-to-evidence navigation
with explicit unknown states. Status: **implemented, tested, demoed**
(services/investigation-ui, 11 service tests passing).

## What shipped

`services/investigation-ui` — small FastAPI app (fastapi==0.118.3,
httpx==0.28.1, uvicorn==0.38.0 pinned in the local pyproject) + one
single-page HTML/JS file (vanilla, no build toolchain), plus server-rendered
no-JS views at `/view/*` that are curl-addressable.

Views:

- **Runs list** — run_id, agent, release, span + privileged-span count,
  verification summary by state, correlation summary by state per run.
- **Trace drilldown** — span tree per trace; every privileged tool span shows
  its evidence reference (`receipt_hash`), the verification status rendered
  from the **full ADR-0001 enum**
  (`valid | invalid | unknown_key | unsupported_schema | pending |
  unavailable | not_applicable`) and the correlation state (ADR-0002:
  `matched | receipt_missing | trace_missing | ambiguous | late_arrival |
  duplicate | pending`). Explicit unknown states get amber badges
  (`.badge-unknown`); blank statuses are asserted absent by tests. Spans with
  no receipt show an explicit "no receipt observed (explicit gap)" badge —
  absence is a coverage gap, never silence (ADR-0002 invariant 2).
- **Evidence panel** — metadata only: receipt_hash, schema_version (from the
  signed `typ`), gate decision, policy_ref, tool, trace_id, event_time;
  *Verify offline* button runs `evidence_plane.classify` (raucle's own
  ProvenanceVerifier) over the canonical `{receipt_hash, jws}` bytes from the
  read-only store and surfaces the verifier output summary
  (checks_performed, state, verifier pin). The raw JWS is **never rendered**
  — it is only linked for download (`Content-Disposition: attachment`).
- **Findings panel** — RULE-01 output (rule_id, severity, confidence,
  evidence refs); suppressed findings are **retained** with
  `suppression_reason`.

Data source: everything local — canonical evidence store copy
(sha256 `0afe93c937b96c...`, byte-identical to the obs01 spike receipts),
fixture runs, hand-built synthetic index rows (never canonical evidence),
a verification index, PUBLIC-only trust roots, and a documented SEC-001
suppression. Correlation index rows are computed at load time by the COR-01
`reconcile` engine (at=None ⇒ all windows closed, so demo states are
terminal). Live Langfuse traces are optionally available via `env` keys read
at runtime only (`GET /api/live/traces`); unconfigured ⇒ explicit
`{"available": false}` and skippable.

Threat-model T5 hardening (tested):

- Server-side views escape **every** interpolated value (`html.escape`);
  the SPA uses **no `innerHTML` at all** — everything lands via
  `textContent`. A fixture attribute carrying `<script>alert('ui-01-xss')</script>`
  and a `javascript:` link probe render as inert host text (asserted, raw
  forms must not appear in any HTML response).
- No auto-link resolution, no external fetches from the page, no secret
  display (JWS value, trust keys, env values never appear in responses;
  asserted with `"eyJhbG" not in …`).

The offline verifier: raucle 0.23.5's `ProvenanceVerifier` takes
`dict[str, bytes]` PEMs; the data loader encodes registry PEMs to bytes
(raise-visible compatibility note in `data.py`). When raucle is not
importable the endpoint returns an explicit `unavailable` state with the
reason — never a fabricated verdict.

## Acceptance mapping

Plan criterion: *"analyst investigation under five minutes from alert to
relevant run"*. The scripted flow (runs list → drilldown → privileged span →
evidence panel → verify offline → findings receipt_missing) is fully
curl-level, captured verbatim in
`services/investigation-ui/transcript.txt`; **wall time 0.14 s** for the
whole chain — orders of magnitude inside five minutes. Human UI flow is the
same four clicks in the SPA.

Per-span UX guidance (competitor-analysis: verification status + evidence
navigation on the same span surface) is met: status badges sit on the row;
the receipt_hash is a one-click hop to the evidence panel; findings live on
the same run surface with confidence and suppression context; unknowns are
explicit with detail tooltips; no auto-intent attribution anywhere
(findings state discrepancies only).

Demo coverage across the full enums:

- verification: valid (obs01 receipts + one synthetic), unknown_key,
  unsupported_schema, pending, unavailable, not_applicable all present in
  run-sim-02; invalid asserted by the state space itself (classify maps it;
  no ingest-time invalid fixture was needed).
- correlation: matched, ambiguous, duplicate, late_arrival, receipt_missing
  demoed; trace_missing/duplicate-collapse semantics come from the COR-01
  engine and are exercised in tests/services/test_correlation.py (a
  receipt-only trace_missing exists in this demo's data-space but has no
  span surface, matching reality — receipts with no trace have nothing to
  hang a span on).

Real (non-synthetic) demo data:

- obs01 receipts (read_file allow + write_file deny on trace
  `e8263e...3375`) reconcile to `ambiguous` — COR-01 keys receipts by
  trace_id, and this single trace carries two distinct receipt hashes (one
  per tool call). The ambiguity is surfaced verbatim with a
  "needs human/ingest review" note rather than silently resolved.
  Verifying either receipt offline returns `valid`
  (`raucle 0.23.5 (git 63edacd)`, checks listed in the transcript).

## Gaps (deferred)

- Dashboard rollups across runs (trend lines, per-release verification
  coverage rates) — the runs-list summaries are the minimal surface; a
  cross-run rollup view was not built.
- SIEM / external tracker links deferred entirely (also consistent with T5:
  auto-link resolution is off by design; any future link-out must be
  an explicit, allow-listed affordance, not implicit URL detection).
- Live Langfuse integration is read-only, index-projected, and
  unauthenticated-key-from-env only; span-tree hydration from live
  observations (vs. fixture spans) not wired into drilldown.
- trace_missing has no dedicated span surface (it is receipt-side).
- Verification states come from the verification *index* at rest; the UI
  re-verifies on demand ("Verify offline") but does not yet reconcile
  at-rest vs. freshly-verified states on the drilldown row.
- Single-user, no auth on the local demo server — fine for the spike,
  not a deployment posture.

## Verification

- `pytest services/investigation-ui/tests` → 11 passed.
- Root suite unchanged: 220 passed, 3 skipped.
- `ruff check .` clean for all investigation-ui files (remaining 12 findings
  are pre-existing in `deploy/reference/` and `tests/load/`, untouched).
- `ruff format` applied to the service; no canonical evidence bytes
  modified (invariant 1 asserted by a read-only test).