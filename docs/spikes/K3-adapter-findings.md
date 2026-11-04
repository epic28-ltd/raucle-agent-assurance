# K3 — LangGraph Gate Adapter: Findings (EPIC M)

<!-- SPDX-License-Identifier: Apache-2.0 -->

Local-only spike, nothing external contacted. Code:
`integrations/langgraph-adapter/` (Apache-2.0). raucle pinned worktree
`~/Projects/raucle-63edacd` → distribution pin **`raucle 0.23.5 (git 63edacd)`**
(`raucle.__version__` is stale at 0.22.0; the pin constant keys on the
distribution, not the package version — same rule as packages/raucle-adapter).

## Design

- **Enforcement point = `wrap_tool_call` middleware.** It receives
  `ToolCallRequest{tool_call:{name,args,id}, state, runtime}` and an
  `execute(request)` callable; vetoing is simply *not calling* `execute`.
  That makes "the tool body never runs on deny" structurally true, not a
  flag the tool has to honour.
- **Dependency-free core.** The middleware works without langgraph installed:
  `runtimes.py` mirrors `ToolCallRequest` as a local TypedDict and swaps the
  real `AgentMiddleware` base class in via try/except when langchain is
  importable. All unit tests run on the mirror; the integration tests
  (`pytest.importorskip("raucle")`) run the real `RaucleGateway` in-process.
- **Layer split.** `GateClient` protocol + two impls:
  - `InProcessRaucleGate` — wraps a real `RaucleGateway` in the same
    interpreter; `check_tool_call(tool, args, agent_id, source, trace_id)` is
    called with `trace_id = supplied correlation id or tool_call.id`;
    escalation is resolved to **deny** until an approval workflow exists.
  - `HttpGateClient` — POST JSON, urllib, timeout **80 ms default**, no
    retries in the enforcement path (one attempt per tool call);
    `fail_open` is per-client, but the middleware enforces its own
    fail-closed default independently.
- **Observability is callback-only.** `SpanAttributeSink.set_tool_attributes`
  and `AuditSink.on_gate_event` interfaces mean no OpenTelemetry import in
  the package; a thin otel sink is a user-side ~5-line adapter.
- **Policy exception path:** `on_deny="raise"` raises `ToolCallDeniedError`
  instead of returning the synthetic denied tool message.

## Wiring snippet

```python
from langchain.agents.middleware import AgentMiddleware
from langgraph.prebuilt import create_react_agent

from oaa_langgraph_adapter import RaucleGateMiddleware, HttpGateClient

gate_mw = RaucleGateMiddleware(
    gate=HttpGateClient("http://127.0.0.1:8080/v1/gate/check"),
    agent_id="agent:my-agent",
    fail_open=False,  # default; gate errors veto
    on_deny="message",  # default: denied tool message; "raise" raises ToolCallDeniedError
    span_sink=my_otel_sink,  # set_tool_attributes(call_id, {"oaa.receipt_hash": ..., "oaa.verification": "signed"})
    audit_sink=my_audit,  # on_gate_event(event) with decision, trace_id, gate/adapter latency
)
agent = create_react_agent(model, tools, middleware=[gate_mw])
```

In-process variant:

```python
from oaa_langgraph_adapter import InProcessRaucleGate

gate_mw = RaucleGateMiddleware(InProcessRaucleGate(RaucleGateway(cfg), agent_id="agent:x"))
```

## Semantics locked in tests (`tests/adapter/`)

| Scenario | Outcome |
|---|---|
| allow + receipt | tool runs once; span attrs `oaa.receipt_hash` + `oaa.verification=signed`; correlation id → gate `trace_id` |
| allow **without** receipt | **veto** — an unverified allow is worth exactly a deny (no receipt ⇒ no verification state) |
| deny / escalate (any `fail_open`) | tool NOT invoked; denied tool message `denied by Raucle Agent Trust gate: <reason>` |
| gate exception, `fail_open=False` (default) | veto, tool NOT invoked |
| gate exception, `fail_open=True` | tool runs, span attrs `oaa.verification="unverified"`, never `oaa.receipt_hash` |
| real raucle allow/deny (integration) | signed receipt keyed by the correlation id lands in the pinned gateway's receipt store (`x_gate.trace_id`) |

Every deny path — table-test invariants — asserts the executor callable was
never invoked. Latency (gate + adapter overhead) rides the audit event;
`adapter_latency_us >= 0` measured around the single gate call, no retries.

## Latency notes (measured)

In-process `RaucleGateway` (pinned worktree), 200 iterations, same-process
middleware round trip including receipt signing:

- allow: p50 ≈ **0.74 ms**, p95 ≈ **1.2 ms**
- deny: p50 ≈ **0.76 ms**, p95 ≈ **1.0 ms**

That is ≈1–2 % of the 80 ms default HTTP budget; the HTTP client default
timeout (80 ms) is the latency budget knob, not an expected spend. The
adapter adds only one dict build + sink calls around the gate call
(microseconds). Nothing in the enforcement path retries or queues.

## Gaps / next steps

1. **State/context propagation.** `trace_id` extraction greps common keys
   (`trace_id`, `thread_id`, `oaa_trace_id`) off `request["runtime"]` /
   `state` via a pluggable `trace_context_getter`; LangGraph has no standard
   trace-id field on `ToolCallRequest`, so a per-team getter may be needed.
   `agent_id`/`source` are middleware config, not derived from graph state.
2. **Streaming.** `wrap_tool_call` vetoes before the StreamedToolNode emits
   tokens, so a denied call cannot leak streamed tool output — but denial
   surfacing mid-stream (e.g. emitting only the denied message into the
   stream) is runtime-dependent and untested here; the synthetic denied
   message may appear as one message rather than streaming chunks.
3. **Async.** Only the sync `wrap_tool_call` hook is implemented; async graphs
   need `awrap_tool_call` (same body) once langchain versions settle the hook
   name.
4. **Escalation.** `decision="escalate"` resolves to deny; a PR-E-style
   approval resubmission path (`approval_id`) is not wired.
5. **Sub-attribute granularity.** Span attributes are set post-decision via
   the sink; there is no pre-gate attempt span. A start/stop pair would make
   gate-time vs adapter-time visible in traces.
6. **Version pinning drift.** `InProcessRaucleGate` keys everything on the
   distribution pin constant; a running gateway must not be older/newer
   policy-semantics than the pin (see packages/raucle-adapter README).