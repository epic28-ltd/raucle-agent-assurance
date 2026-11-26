# SPDX-License-Identifier: Apache-2.0
"""W3C trace-context getter tests (issue 111).

The getter is the adapter's propagation seam: stdlib-only (this package
never imports OpenTelemetry), it adopts a valid incoming traceparent's
trace id when no legacy trace key exists, preserves an existing trace id
otherwise, and falls back to the default getter on malformed or absent
headers. Malformed headers must never raise and must never change the
enforcement decision.
"""

from __future__ import annotations

from typing import ClassVar

import pytest
from oaa_langgraph_adapter import (
    GateDecision,
    GateTraceContext,
    RaucleGateMiddleware,
    w3c_trace_context_getter,
)
from oaa_langgraph_adapter.middleware import _default_trace_context

VALID_TP = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
VALID_TP_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
VALID_TS = "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"


def make_request(name="read_file", args=None, call_id="call-1", **state):
    return {
        "tool_call": {"name": name, "args": args or {"path": "/var/oaa-demo/x"}, "id": call_id},
        "state": dict(state),
    }


class FakeGateClient:
    def __init__(self, decisions):
        self.decisions = list(decisions)
        self.requests = []

    def check_tool_call(self, *, tool, args, call_id, trace_id, agent_id, source):
        self.requests.append({"tool": tool, "call_id": call_id, "trace_id": trace_id})
        return self.decisions.pop(0)


class StubExecutor:
    def __init__(self):
        self.calls = []

    def __call__(self, request):
        self.calls.append(request)
        return "ran"


class AuditSink:
    def __init__(self):
        self.events = []

    def on_gate_event(self, event):
        self.events.append(dict(event))


ALLOW = GateDecision(
    decision="allow", reason="ok", receipt_hash="sha256:abc", latency_us=150, raw={}
)


# -- getter -------------------------------------------------------------------


def test_no_headers_matches_default_getter():
    request = make_request(trace_id="t-123")
    assert w3c_trace_context_getter(request) == _default_trace_context(request)
    assert w3c_trace_context_getter(request).trace_id == "t-123"
    assert w3c_trace_context_getter(make_request()).extra == {}


def test_valid_traceparent_adopts_w3c_trace_id():
    ctx = w3c_trace_context_getter(make_request(traceparent=VALID_TP))
    assert ctx.trace_id == VALID_TP_TRACE_ID
    assert ctx.extra["traceparent"] == VALID_TP


def test_valid_traceparent_with_tracestate():
    ctx = w3c_trace_context_getter(make_request(traceparent=VALID_TP, tracestate=VALID_TS))
    assert ctx.trace_id == VALID_TP_TRACE_ID
    assert ctx.extra["traceparent"] == VALID_TP
    assert ctx.extra["tracestate"] == VALID_TS


def test_traceparent_without_tracestate_omits_key():
    ctx = w3c_trace_context_getter(make_request(traceparent=VALID_TP))
    assert "tracestate" not in ctx.extra


def test_legacy_trace_id_is_preserved_over_w3c_trace_id():
    ctx = w3c_trace_context_getter(make_request(trace_id="t-123", traceparent=VALID_TP))
    assert ctx.trace_id == "t-123"
    assert ctx.extra["traceparent"] == VALID_TP


def test_header_in_runtime_carrier_is_found():
    request = {
        "tool_call": {"name": "t", "args": {}, "id": "call-1"},
        "runtime": {"traceparent": VALID_TP},
    }
    assert w3c_trace_context_getter(request).trace_id == VALID_TP_TRACE_ID


def test_header_in_object_metadata_is_found():
    class State:
        metadata: ClassVar[dict] = {"traceparent": VALID_TP}

    request = {"tool_call": {"name": "t", "args": {}, "id": "call-1"}, "state": State()}
    ctx = w3c_trace_context_getter(request)
    assert ctx.trace_id == VALID_TP_TRACE_ID


@pytest.mark.parametrize(
    "traceparent",
    [
        "not-a-header",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
        f"00-{VALID_TP_TRACE_ID.upper()}-00f067aa0ba902b7-01",
        "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
        "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
        "ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
        "a" * 600,
        "",
        "   ",
    ],
)
def test_malformed_traceparent_falls_back_to_default(traceparent):
    request = make_request(trace_id="t-123", traceparent=traceparent)
    ctx = w3c_trace_context_getter(request)
    assert ctx.trace_id == "t-123"
    assert ctx.extra == {}


def test_malformed_traceparent_without_legacy_key_falls_back_to_call_id():
    # No usable correlation id at all: the middleware's `ctx.trace_id or
    # call_id` fallback applies, exactly as with the default getter.
    ctx = w3c_trace_context_getter(make_request(traceparent="garbage"))
    assert ctx == GateTraceContext()


def test_tracestate_alone_is_ignored():
    ctx = w3c_trace_context_getter(make_request(tracestate=VALID_TS))
    assert ctx == GateTraceContext()


def test_oversized_tracestate_is_dropped_not_forwarded():
    ctx = w3c_trace_context_getter(make_request(traceparent=VALID_TP, tracestate="x" * 6000))
    assert ctx.trace_id == VALID_TP_TRACE_ID
    assert "tracestate" not in ctx.extra


def test_never_raises_on_hostile_shapes():
    for request in (
        None,
        ["not", "a", "mapping"],
        123,
        {"tool_call": None, "state": object()},
        {"tool_call": {}, "state": {"traceparent": 12345}},
        {"tool_call": {}, "state": {"traceparent": VALID_TP, "tracestate": 99}},
        {"tool_call": {}, "runtime": {"traceparent": [VALID_TP]}},
    ):
        assert isinstance(w3c_trace_context_getter(request), GateTraceContext)


# -- middleware integration (pins the event forwarding) ------------------------


def test_middleware_forwards_headers_to_gate_event():
    gate = FakeGateClient([ALLOW])
    audits = AuditSink()
    mw = RaucleGateMiddleware(
        gate, audit_sink=audits, trace_context_getter=w3c_trace_context_getter
    )
    ex = StubExecutor()
    mw.wrap_tool_call(make_request(traceparent=VALID_TP, tracestate=VALID_TS), ex)

    assert len(ex.calls) == 1
    assert gate.requests[0]["trace_id"] == VALID_TP_TRACE_ID
    event = audits.events[0]
    assert event["trace_id"] == VALID_TP_TRACE_ID
    assert event["traceparent"] == VALID_TP
    assert event["tracestate"] == VALID_TS


def test_middleware_default_getter_events_carry_no_headers():
    # No regression: the default getter never populates extra, so events
    # keep their historical shape.
    gate = FakeGateClient([ALLOW])
    audits = AuditSink()
    mw = RaucleGateMiddleware(gate, audit_sink=audits)
    mw.wrap_tool_call(make_request(), StubExecutor())

    event = audits.events[0]
    assert "traceparent" not in event
    assert "tracestate" not in event
    assert event["trace_id"] == "call-1"


def test_malformed_header_does_not_change_the_decision():
    # Category 9 seed: malformed trace headers must not flip a decision.
    gate = FakeGateClient([ALLOW])
    audits = AuditSink()
    mw = RaucleGateMiddleware(
        gate, audit_sink=audits, trace_context_getter=w3c_trace_context_getter
    )
    ex = StubExecutor()
    mw.wrap_tool_call(make_request(traceparent="00-bad"), ex)

    assert len(ex.calls) == 1  # allow stayed allow
    assert "traceparent" not in audits.events[0]
    assert audits.events[0]["trace_id"] == "call-1"
