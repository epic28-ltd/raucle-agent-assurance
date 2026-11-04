# OAA LangGraph Adapter (EPIC M K3)

<!-- SPDX-License-Identifier: Apache-2.0 -->

Enforce-before adapter that routes every LangGraph tool call through the Raucle
Agent Trust gate before the tool body runs. `langgraph`/`langchain` are
**not** required to install or test this package: the middleware mirrors the
`ToolCallRequest` shape with a local TypedDict and registers with
`AgentMiddleware` only when langchain is importable (try/except).

See `docs/spikes/K3-adapter-findings.md` at the repo root for design notes,
latency measurements and known gaps.

Quick wiring (see the findings doc for the full snippet):

```python
from oaa_langgraph_adapter import RaucleGateMiddleware, HttpGateClient

mw = RaucleGateMiddleware(
    gate=HttpGateClient("http://127.0.0.1:8080/v1/gate/check"),
    agent_id="agent:my-agent",
)
agent = create_react_agent(model, tools, middleware=[mw])  # langchain >= 0.3
```

Invariants honoured here (ADR-0001 / EPIC M):

- **monitoring never enforcement-authority** — this adapter *calls* the gate;
  it is not the gate.
- **correlation id in → signed receipt out** — the `tool_call` id (or a
  supplied trace id) is the gate's `trace_id`; an allow carries a
  `receipt_hash` that lands on span attributes via a callback sink
  (no direct OpenTelemetry import).
- **deny = the tool body must not run** — verified in every test deny path.
- **fail closed by default** — a gate error vetoes the call unless
  `fail_open=True` is explicitly set.
- **no retries in the enforcement path** — one gate call per tool call.