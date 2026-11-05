# SPDX-License-Identifier: Apache-2.0
"""Middleware table tests: veto/allow/latency/fail_open/fail_closed.

Runs entirely without langgraph installed (local TypedDict mirror). Every
deny path asserts the tool body NEVER runs.
"""

import pytest
from oaa_langgraph_adapter import (
    GateDecision,
    GateTraceContext,
    RaucleGateMiddleware,
    ToolCallDeniedError,
)


class FakeGateClient:
    """Scripted gate: returns queued decisions, records every request."""

    def __init__(self, decisions, error=None):
        self.decisions = list(decisions)
        self.error = error
        self.requests = []

    def check_tool_call(self, *, tool, args, call_id, trace_id, agent_id, source):
        self.requests.append(
            {
                "tool": tool,
                "args": dict(args),
                "call_id": call_id,
                "trace_id": trace_id,
                "agent_id": agent_id,
                "source": source,
            }
        )
        if self.error:
            raise self.error
        return self.decisions.pop(0)


class StubExecutor:
    """The tool body. It must never run on a deny path."""

    def __init__(self, result="ran:"):
        self.result = result
        self.calls = []

    def __call__(self, request):
        self.calls.append(request)
        return self.result + str(request["tool_call"]["args"])


class SpanSink:
    def __init__(self):
        self.attrs = {}

    def set_tool_attributes(self, call_id, attributes):
        self.attrs[call_id] = dict(attributes)


class AuditSink:
    def __init__(self):
        self.events = []

    def on_gate_event(self, event):
        self.events.append(dict(event))


def make_request(name="read_file", args=None, call_id="call-1"):
    return {
        "tool_call": {
            "name": name,
            "args": args or {"path": "/var/oaa-demo/synthetic/x"},
            "id": call_id,
        }
    }


ALLOW = GateDecision(
    decision="allow",
    reason="ok",
    receipt_hash="sha256:abc",
    latency_us=150,
    raw={"policy": "read_file.yaml"},
)
DENY = GateDecision(decision="deny", reason="policy: no rule for path", latency_us=90, raw={})
ESCALATE = GateDecision(decision="deny", reason="escalation unresolved", latency_us=10, raw={})


# --- allow path -----------------------------------------------------------


def test_allow_with_receipt_runs_tool_and_attaches_span_attrs():
    gate = FakeGateClient([ALLOW])
    spans, audits = SpanSink(), AuditSink()
    mw = RaucleGateMiddleware(gate, span_sink=spans, audit_sink=audits, agent_id="agent:t")
    ex = StubExecutor()
    out = mw.wrap_tool_call(make_request(), ex)

    assert out == "ran:{'path': '/var/oaa-demo/synthetic/x'}"
    assert len(ex.calls) == 1  # tool body ran exactly once
    attrs = spans.attrs["call-1"]
    assert attrs["oaa.receipt_hash"] == "sha256:abc"
    assert attrs["oaa.verification"] == "signed"
    assert attrs["oaa.policy"] == "read_file.yaml"
    assert attrs["oaa.trace_id"] == "call-1"
    assert audits.events[0]["decision"] == "allow"
    assert audits.events[0]["fail_open"] is False


def test_allow_without_receipt_vetoes():
    # An allow with no signed receipt carries no verification state: veto.
    gate = FakeGateClient([GateDecision(decision="allow", reason="ok")])
    mw = RaucleGateMiddleware(gate, span_sink=SpanSink())
    ex = StubExecutor()
    out = mw.wrap_tool_call(make_request(), ex)

    assert ex.calls == []  # tool body NEVER ran
    assert "denied by Raucle Agent Trust gate" in str(out)


def test_escalation_is_denied_and_tool_not_invoked():
    gate = FakeGateClient([GateDecision(decision="escalate", reason="needs human")])
    mw = RaucleGateMiddleware(gate)
    ex = StubExecutor()
    out = mw.wrap_tool_call(make_request(), ex)

    assert ex.calls == []
    assert "denied by Raucle Agent Trust gate: needs human" in str(out)
    assert "needs human" in out["content"]


# --- deny paths (table) ---------------------------------------------------


@pytest.mark.parametrize(
    ("decision", "fail_open"),
    [
        (DENY, False),
        (DENY, True),  # fail_open never overrides an explicit gate DENY
        (ESCALATE, False),
    ],
)
def test_table_deny_paths_never_run_tool(fail_open, decision):
    gate = FakeGateClient([decision])
    audits = AuditSink()
    mw = RaucleGateMiddleware(gate, fail_open=fail_open, audit_sink=audits, on_deny="message")
    ex = StubExecutor()
    out = mw.wrap_tool_call(make_request(), ex)

    assert ex.calls == []  # THE invariant: tool body never runs on deny
    assert "denied by Raucle Agent Trust gate" in out["content"]
    assert decision.reason in out["content"]
    assert out["tool_call_id"] == "call-1"
    assert audits.events[0]["decision"] == "deny"
    assert audits.events[0]["tool"] == "read_file"


def test_table_deny_with_raise_config_raises_policy_exception():
    gate = FakeGateClient([DENY])
    mw = RaucleGateMiddleware(gate, on_deny="raise")
    ex = StubExecutor()

    with pytest.raises(ToolCallDeniedError) as exc_info:
        mw.wrap_tool_call(make_request(), ex)

    assert ex.calls == []
    assert "denied by Raucle Agent Trust gate" in str(exc_info.value)


# --- gate failure: fail closed by default ---------------------------------


def test_gate_error_fail_closed_vetoes_tool_not_run():
    gate = FakeGateClient([], error=RuntimeError("socket hang-up"))
    mw = RaucleGateMiddleware(gate)
    ex = StubExecutor()
    out = mw.wrap_tool_call(make_request(), ex)

    assert ex.calls == []
    assert "gate failure" in out["content"]
    assert "fail_open=False" in out["content"]


def test_gate_error_fail_open_runs_tool_without_receipt():
    gate = FakeGateClient([], error=RuntimeError("socket hang-up"))
    spans = SpanSink()
    mw = RaucleGateMiddleware(gate, fail_open=True, span_sink=spans)
    ex = StubExecutor()
    out = mw.wrap_tool_call(make_request(), ex)

    assert out == "ran:{'path': '/var/oaa-demo/synthetic/x'}"  # fail_open lets the call through
    assert ex.calls and len(ex.calls) == 1
    assert spans.attrs["call-1"]["oaa.verification"] == "unverified"
    assert "oaa.receipt_hash" not in spans.attrs["call-1"]


# --- correlation id & latency ---------------------------------------------


def test_correlation_id_passed_to_gate_call_id_as_trace_id_fallback():
    gate = FakeGateClient([ALLOW])
    mw = RaucleGateMiddleware(gate)
    mw.wrap_tool_call(make_request(call_id="call-42"), StubExecutor())

    req = gate.requests[0]
    assert req["call_id"] == "call-42"
    assert req["trace_id"] == "call-42"  # call id used when no trace context


def test_trace_id_from_context_wins_over_call_id():
    gate = FakeGateClient([ALLOW])
    mw = RaucleGateMiddleware(gate)
    request = make_request(call_id="call-42")
    request["state"] = {"trace_id": "trace-7"}
    mw.wrap_tool_call(request, StubExecutor())

    assert gate.requests[0]["trace_id"] == "trace-7"


def test_custom_trace_context_getter_used():
    gate = FakeGateClient([ALLOW])
    mw = RaucleGateMiddleware(
        gate,
        trace_context_getter=lambda req: GateTraceContext(
            trace_id="t-9", agent_id="agent:ctx", source="worker"
        ),
    )
    mw.wrap_tool_call(make_request(), StubExecutor())

    req = gate.requests[0]
    assert req["trace_id"] == "t-9"
    assert req["agent_id"] == "agent:ctx"
    assert req["source"] == "worker"


def test_latency_recorded_in_audit_event():
    gate = FakeGateClient([ALLOW])
    audits = AuditSink()
    mw = RaucleGateMiddleware(gate, audit_sink=audits)
    mw.wrap_tool_call(make_request(), StubExecutor())

    ev = audits.events[0]
    assert ev["gate_latency_us"] == ALLOW.latency_us
    assert ev["adapter_latency_us"] >= 0  # adapter overhead measured, no retries


def test_args_forwarded_verbatim_to_gate():
    gate = FakeGateClient([ALLOW])
    mw = RaucleGateMiddleware(gate)
    args = {"path": "/var/oaa-demo/evd-allow.txt", "nested": {"k": [1, 2]}}
    mw.wrap_tool_call(make_request(args=args), StubExecutor())

    assert gate.requests[0]["args"] == args


def test_agent_id_and_source_defaults_forwarded():
    gate = FakeGateClient([ALLOW])
    mw = RaucleGateMiddleware(gate, agent_id="agent:cfg", source="cli")
    mw.wrap_tool_call(make_request(), StubExecutor())

    req = gate.requests[0]
    assert req["agent_id"] == "agent:cfg"
    assert req["source"] == "cli"


def test_invalid_on_deny_config_rejected():
    with pytest.raises(ValueError, match="on_deny"):
        RaucleGateMiddleware(FakeGateClient([]), on_deny="explode")
