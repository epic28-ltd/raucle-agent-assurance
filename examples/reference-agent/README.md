# examples/reference-agent

The OBS-01 vertical-slice reference agent and its de-risking probe scripts,
imported from the 4 Nov spike.

- `reference_agent.py` — synthetic OTel trace (AGENT root → LLM stub,
  RETRIEVER, TOOL) using OpenInference span kinds and the `oaa.*` attribute
  namespace. Metadata-only by default: `oaa.content_class` carries only a
  class, never a raw secret.
- `verify_p1.py` — P1 probe: attribute round-trip fidelity (diffs
  originals.json against Langfuse readback).
- `p2_p5_correlation.py` — P2/P5 probes: score attachment + raucle
  receipt-to-trace correlation (allow AND deny), receipts stored verbatim,
  sha256-checked before/after attach.
- `p3_outage.py` — P3 probe: backend-outage behaviour (stock OTLP exporter
  silently drops spans on connection refused → bounded-retry requirement).
- `originals.json`, `p1_report.json`, `p2_report.json`, `p3_report.json`,
  `p5_receipts_report.json` — outputs from the recorded spike run.

## Running

Requires the local Langfuse stack (deploy/compose/README.md) up on
127.0.0.1:3301 and a project with OTLP API keys in a local `obs.env`
(git-ignored; variable names LANGFUSE_INIT_PROJECT_PUBLIC_KEY /
LANGFUSE_INIT_PROJECT_SECRET_KEY):

```bash
python3 -m pip install opentelemetry-sdk opentelemetry-exporter-otlp
python reference_agent.py
python verify_p1.py && python p2_p5_correlation.py && python p3_outage.py
```

`sample-receipts.jsonl` is a truncated sample receipt envelope pair from the
recorded run (display shorthand, not byte-complete — see findings).

## OBS-03 — second workflow: adapter contract reuses without core rewrites

`workflow_two.py` + `workflow_two_smoke.py` prove the LangGraph adapter
contract (RaucleGateMiddleware + GateClient + the two sink callbacks)
reuses as-is for a SECOND synthetic workflow, `compliance-ticket-triage`,
with a deliberately different shape:

- multi-step instead of flat: AGENT root -> RETRIEVER `retrieve-ticket`
  -> RETRIEVER `fetch-customer-context` -> LLM stub `propose-action`
  -> gated TOOL `file_write` -> workflow exit;
- a designed failure path: an OUT-OF-SCOPE write (`/tmp/oaa-scope/finance/...`)
  the gate denies; the middleware vetoes (the write executor NEVER runs) and
  the tool-side `FileWriteLedger` shows the ABSENCE of the row — negative
  evidence that enforcement held;
- the same `oaa.*` namespace with the run-two prefix (`oaa-run2-*`,
  `oaa-trace2-*`) and the same `SpanAttributeSink` /
  `AuditSink` callback contracts, implemented as plain classes here
  (loopback-only synthetic `ScopeGateClient` fills the `GateClient` protocol,
  so no raucle worktree is needed to prove the path).

Shared adapter surfaces used unchanged
(`integrations/langgraph-adapter/src/oaa_langgraph_adapter/`):
`RaucleGateMiddleware.wrap_tool_call`, `GateClient.check_tool_call`,
`GateDecision`, `SpanAttributeSink.set_tool_attributes(call_id, attrs)`,
`AuditSink.on_gate_event(event)` — including the veto-without-receipt rule
(`allow` with no signed receipt denies too) and fail_open=False default.
Differences live entirely in the workflow (shape, gate policy, run-id prefix),
not in the contract. Gaps (still open): async/streaming tool-call execution,
live escalation-resolution, real raucle gate in this second-workflow smoke
(the loopback synthetic client is used; the in-process/pinned-raucle paths
remain covered by the adapter's own test suite). The optional Langfuse push
re-uses the stock OTLP exporter but SKIPS unless local creds exist
(`obs.env`/`LANGFUSE_INIT_*` env vars) and 127.0.0.1-only — no external calls.

Run: `PYTHONPATH=integrations/langgraph-adapter/src .venv/bin/python
examples/reference-agent/workflow_two_smoke.py` (local-only; prints span
trees, `oaa.*` readback, gate/ledger evidence, and a PASS/FAIL checklist).
Regression tests: `tests/assurance/test_obs03_workflow_two.py`.