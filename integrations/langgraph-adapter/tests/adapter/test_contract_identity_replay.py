# SPDX-License-Identifier: Apache-2.0
"""Identity, replay and error-handling contracts at the middleware seam.

These tests bind the enforce-before adapter's contracts at its real seam
(``wrap_tool_call`` and the single gate call behind it). They run entirely
without langgraph installed (local TypedDict mirror), so they hold in any
environment, and they hold no opinion about the framework version.

Contracts bound here:

- identity: the middleware never fabricates an acting identity. An empty
  configured identity reaches the gate as empty, the default getter never
  lifts an agent id out of graph state, a getter-supplied identity is
  forwarded verbatim and lands identical on the audit event, and an allow
  without a signed receipt is a veto even with an empty identity.
- replay: there is no decision or receipt cache. An invocation repeated with
  an identical correlation id issues exactly one further gate call with the
  same id; a recorded ALLOW never pre-authorises a later call locally.
- error handling: a gate exception is exactly one gate call (no retry in the
  enforcement path); under the default fail-closed mode the tool body never
  runs and the audit event carries the error; under explicit ``fail_open``
  the call proceeds unverified with no receipt hash on the span.
"""

from oaa_langgraph_adapter import (
    GateDecision,
    GateTraceContext,
    RaucleGateMiddleware,
)
from test_middleware import ALLOW, AuditSink, FakeGateClient, SpanSink, StubExecutor, make_request

ALLOW_NO_RECEIPT = GateDecision(decision="allow", reason="ok", receipt_hash=None, latency_us=5)
ALLOW_ALT = GateDecision(
    decision="allow", reason="ok", receipt_hash="sha256:def", latency_us=5, raw={"policy": "p.yaml"}
)


# --- identity contract ----------------------------------------------------


def test_empty_configured_agent_id_reaches_gate_as_empty_never_fabricated():
    # An empty identity must not be replaced by a placeholder or default:
    # the gate decides on unattributed calls, so it must see the truth.
    gate = FakeGateClient([ALLOW])
    mw = RaucleGateMiddleware(gate, agent_id="")
    mw.wrap_tool_call(make_request(), StubExecutor())

    assert len(gate.requests) == 1
    assert gate.requests[0]["agent_id"] == ""


def test_default_getter_does_not_lift_agent_id_out_of_graph_state():
    # Identity is middleware configuration (K3 gap, kept a contract): a
    # hostile or collaborative runtime state carrying an "agent_id" key is
    # NOT adopted by the default getter.
    gate = FakeGateClient([ALLOW])
    mw = RaucleGateMiddleware(gate, agent_id="agent:config")
    request = {
        "tool_call": {"name": "read_file", "args": {"path": "/var/x"}, "id": "call-1"},
        "state": {"agent_id": "agent:planted-in-state"},
    }
    mw.wrap_tool_call(request, StubExecutor())

    assert gate.requests[0]["agent_id"] == "agent:config"


def test_getter_supplied_identity_is_forwarded_verbatim_and_wins():
    # A custom getter's identity is passed through unmodified (the adapter
    # is not an identity authority), and the decision stays the gate's.
    gate = FakeGateClient([ALLOW])
    mw = RaucleGateMiddleware(
        gate,
        agent_id="agent:config",
        trace_context_getter=lambda request: GateTraceContext(
            agent_id="agent:from-context", trace_id="t-1"
        ),
    )
    executed = mw.wrap_tool_call(make_request(), StubExecutor())

    assert gate.requests[0]["agent_id"] == "agent:from-context"
    assert executed == "ran:{'path': '/var/oaa-demo/synthetic/x'}"


def test_identity_is_identical_on_gate_request_and_audit_event():
    gate = FakeGateClient([ALLOW])
    spans, audits = SpanSink(), AuditSink()
    mw = RaucleGateMiddleware(gate, agent_id="agent:t", span_sink=spans, audit_sink=audits)
    mw.wrap_tool_call(make_request(), StubExecutor())

    assert gate.requests[0]["agent_id"] == "agent:t"
    assert audits.events[0]["agent_id"] == "agent:t"


def test_allow_without_receipt_vetoes_even_with_empty_identity():
    # No signed receipt means no verification state: an unverified allow is
    # worth exactly as much as a deny, whatever the identity carried.
    gate = FakeGateClient([ALLOW_NO_RECEIPT])
    mw = RaucleGateMiddleware(gate, agent_id="")
    ex = StubExecutor()
    out = mw.wrap_tool_call(make_request(), ex)

    assert ex.calls == []  # tool body NEVER ran
    assert "denied by Raucle Agent Trust gate" in str(out)


# --- replay contract ------------------------------------------------------


def test_replayed_call_id_gates_again_no_decision_or_receipt_cache():
    # The same tool call id arriving twice is gated twice: the first ALLOW
    # does not pre-authorise the second invocation locally.
    gate = FakeGateClient([ALLOW, ALLOW_ALT])
    mw = RaucleGateMiddleware(gate, agent_id="agent:t")
    ex = StubExecutor()

    first = mw.wrap_tool_call(make_request(call_id="call-1"), ex)
    second = mw.wrap_tool_call(make_request(call_id="call-1"), ex)

    assert first == "ran:{'path': '/var/oaa-demo/synthetic/x'}"
    assert second == "ran:{'path': '/var/oaa-demo/synthetic/x'}"
    assert len(gate.requests) == 2  # exactly one gate call per invocation
    assert gate.requests[0]["call_id"] == "call-1"
    assert gate.requests[1]["call_id"] == "call-1"  # no fabricated uniqueness suffix
    assert gate.requests[0]["agent_id"] == gate.requests[1]["agent_id"]


def test_replayed_call_id_second_gate_decision_applies():
    # A repeat invocation whose second gate verdict is a deny is vetoed: a
    # prior ALLOW on the same correlation id cannot carry it.
    gate = FakeGateClient([ALLOW, GateDecision(decision="deny", reason="revoked")])
    mw = RaucleGateMiddleware(gate, agent_id="agent:t")
    ex = StubExecutor()

    mw.wrap_tool_call(make_request(call_id="call-1"), ex)
    second = mw.wrap_tool_call(make_request(call_id="call-1"), ex)

    assert len(ex.calls) == 1  # only the first invocation ran the tool
    assert "denied by Raucle Agent Trust gate" in str(second)


# --- error handling / no-retry contract -----------------------------------


def test_gate_exception_is_single_gate_call_and_fails_closed():
    gate = FakeGateClient([], error=ConnectionError("gate down"))
    spans, audits = SpanSink(), AuditSink()
    mw = RaucleGateMiddleware(gate, agent_id="agent:t", span_sink=spans, audit_sink=audits)
    ex = StubExecutor()
    out = mw.wrap_tool_call(make_request(), ex)

    assert len(gate.requests) == 1  # no retry in the enforcement path
    assert ex.calls == []  # tool body NEVER ran
    assert "denied by Raucle Agent Trust gate" in str(out)
    assert "gate down" in str(out)
    assert audits.events[0]["decision"] == "deny"
    assert audits.events[0]["error"] == "gate down"
    assert "oaa.receipt_hash" not in spans.attrs.get("call-1", {})


def test_gate_exception_fail_open_runs_unverified_never_signed():
    gate = FakeGateClient([], error=TimeoutError("gate slow"))
    spans, audits = SpanSink(), AuditSink()
    mw = RaucleGateMiddleware(
        gate, agent_id="agent:t", fail_open=True, span_sink=spans, audit_sink=audits
    )
    ex = StubExecutor()
    out = mw.wrap_tool_call(make_request(), ex)

    assert len(gate.requests) == 1  # fail_open does not turn into a retry
    assert out == "ran:{'path': '/var/oaa-demo/synthetic/x'}"
    attrs = spans.attrs["call-1"]
    assert attrs["oaa.verification"] == "unverified"
    assert "oaa.receipt_hash" not in attrs
    assert audits.events[0]["decision"] == "allow"
    assert audits.events[0]["fail_open"] is True
