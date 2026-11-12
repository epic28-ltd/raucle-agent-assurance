# OAA investigation UI (UI-01)

Minimal FastAPI + single-page investigation UI for story **UI-01 —
"Investigate tool calls: trace-to-evidence navigation and explicit unknown
states"** (plan P0). Apache-2.0; no build toolchain (one HTML file, vanilla
JS rendered with `textContent` only).

## Views

- **Runs list** — `/view/runs` (server-rendered, curl-friendly) and `#/` in
  the SPA: run_id, agent, release, span count, verification summary,
  correlation state per privileged tool call.
- **Trace drilldown** — `/view/run/{run_id}` / `#/run/{run_id}` — span tree;
  every privileged span shows its evidence reference (`receipt_hash`),
  verification status from the **full ADR-0001 enum**
  (`valid | invalid | unknown_key | unsupported_schema | pending |
  unavailable | not_applicable`) and correlation state (ADR-0002
  `matched | receipt_missing | trace_missing | ambiguous | late_arrival |
  duplicate | pending`). Explicit unknown states get amber/grey badges and
  are **never silently blank**.
- **Evidence panel** — `/view/receipt/{receipt_hash}` — metadata only
  (receipt_hash, schema_version, gate decision, policy_ref) + *Verify
  offline* button running `evidence_plane.classify` over the canonical
  `{receipt_hash, jws}` bytes. The raw JWS is **never rendered** — only
  linked for download (`Content-Disposition: attachment`).
- **Findings panel** — rule_id, severity, confidence; suppressed findings
  are retained with `suppression_reason` (RULE-01).

## Data

`demo_data/` only — nothing external:

- `evidence_store.jsonl` — byte-verbatim copy of the obs01 canonical
  `receipts.jsonl` (sha256 `0afe93c937b96c...` matches the p5 report).
- `runs.json`, `synthetic_receipt_index.jsonl`,
  `verification_index.jsonl`, `trust_roots.jsonl` (PUBLIC half only — derived
  from the spike's PEM; trust-root PEMs are bytes-encoded for raucle 0.23.5),
  `rules_fixture.json` (documented SEC-001 suppression).
- Correlation index rows are computed at load time with the COR-01 engine.

Optional live Langfuse traces: `GET /api/live/traces` reads
`OAA_LANGFUSE_BASE_URL` / `OAA_LANGFUSE_PUBLIC_KEY` /
`OAA_LANGFUSE_SECRET_KEY` from the environment at runtime only; unconfigured
responses are an explicit `{available: false, reason: ...}` (skippable).
Keys/values are never echoed. The pinned raucle worktree can be pointed at
with `OAA_RAUCLE_SRC` for a working *Verify offline*.

## Auth (R2 slice 1)

Optional; OFF by default (legacy open behaviour when off). With the
hosted OIDC feature enabled (`OAA_HOSTED_OIDC_ENABLED` + issuer; the
console's README and `docs/architecture/hosted-surface-oidc-rbac-r2s1.md`
carry the full env contract), operators authenticate via their
organisation's identity provider; sessions are short-lived receipted
bearers; the viewer/operator/security-admin ladder enforces a
route-level permission matrix with a fail-closed default of view-only —
mutating routes (findings intake, board triage, fleet writes) require
operator; the receipted `/api/roles/{subject}` grant/revoke route
requires security-admin, and roles take effect on the next request.
No-JS data pages (`/view/*`) refuse unauthenticated and
insufficient-role visitors with an explicit HTML login-required page,
never a leaked page.

## Threat-model T5 (hard rules in the tested code path)

- All model/tool content renders as hostile text: server-rendered views
  `html.escape` every value; the SPA has **no `innerHTML`** at all.
- No auto-link resolution (a `javascript:` fixture value renders as inert
  text), no external fetches from the page, no secret display (JWS bodies,
  trust keys, env values never appear in any response).

## Run

    uv pip install --python ../../.venv -e .   # or pip install -r below
    .venv/bin/uvicorn oaa_investigation_ui.app:app --app-dir services/investigation-ui/src --port 8899
    # open http://127.0.0.1:8899/view/runs (or the SPA at /)

## Tests

    .venv/bin/pytest services/investigation-ui/tests

Endpoints exercised with `TestClient`: runs list, drilldown, verify,
findings + unknown-state badge rendering + hostile-text escaping.