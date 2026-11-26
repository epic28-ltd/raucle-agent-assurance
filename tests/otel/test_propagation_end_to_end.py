# SPDX-License-Identifier: Apache-2.0
"""End-to-end propagation tests (issue 111).

W3C trace context flows from a request's state through the LangGraph gate
middleware into OpenTelemetry spans, existing Raucle correlation ids
survive, independent requests never leak context into each other, and
telemetry failure leaves every enforcement decision unchanged.

Categories 1, 2, 3, 8 and 9 of the issue's test plan. No network: the
telemetry pipelines export to in-memory or scripted failing exporters.
"""

from __future__ import annotations

import pytest
from oaa_instrumentation.otel_export import (
    ENV_OTLP_ENDPOINT,
    ENV_OTLP_MAX_ATTEMPTS,
    OtelExportConfig,
    build_export_pipeline,
)
from oaa_instrumentation.otel_gate_sinks import OtelGateSinks
from oaa_langgraph_adapter import (
    GateDecision,
    RaucleGateMiddleware,
    w3c_trace_context_getter,
)
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

TP_1 = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
TP_1_TRACE = "4bf92f3577b34da6a3ce929d0e0e4736"
TP_1_PARENT = "00f067aa0ba902b7"
TP_2 = "00-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bbbbbbbbbbbbbbbb-01"
TP_2_TRACE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
TS = "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"

ALLOW = GateDecision(
    decision="allow",
    reason="ok",
    receipt_hash="sha256:abc",
    latency_us=150,
    raw={"policy": "p.yaml"},
)
DENY = GateDecision(decision="deny", reason="policy: no rule", latency_us=90, raw={})


class FakeGateClient:
    def __init__(self, decisions, error=None):
        self.decisions = list(decisions)
        self.error = error
        self.requests = []

    def check_tool_call(self, *, tool, args, call_id, trace_id, agent_id, source):
        self.requests.append(
            {"tool": tool, "call_id": call_id, "trace_id": trace_id, "agent_id": agent_id}
        )
        if self.error is not None:
            raise self.error
        return self.decisions.pop(0)


class StubExecutor:
    def __init__(self):
        self.calls = []

    def __call__(self, request):
        self.calls.append(request)
        return "ran"


class AlwaysFailingExporter(SpanExporter):
    def __init__(self):
        self.batches = 0

    def export(self, spans) -> SpanExportResult:
        self.batches += 1
        raise ConnectionRefusedError("collector down")


def make_request(call_id="call-1", **state):
    return {
        "tool_call": {"name": "read_file", "args": {"path": "/var/oaa-demo/x"}, "id": call_id},
        "state": dict(state),
    }


def wire_middleware(gate, sinks, **middleware_kwargs):
    return RaucleGateMiddleware(
        gate,
        span_sink=sinks,
        audit_sink=sinks,
        trace_context_getter=w3c_trace_context_getter,
        **middleware_kwargs,
    )


def memory_sinks() -> tuple[OtelGateSinks, InMemorySpanExporter]:
    memory = InMemorySpanExporter()
    setup = build_export_pipeline(
        OtelExportConfig.from_env({ENV_OTLP_ENDPOINT: "https://collector.example/v1/traces"}),
        delegate=memory,
        batched=False,
    )
    return OtelGateSinks(setup.tracer), memory


def failing_sinks() -> tuple[OtelGateSinks, object]:
    setup = build_export_pipeline(
        OtelExportConfig.from_env(
            {
                ENV_OTLP_ENDPOINT: "https://collector.example/v1/traces",
                ENV_OTLP_MAX_ATTEMPTS: "1",
            }
        ),
        delegate=AlwaysFailingExporter(),
        batched=False,
    )
    return OtelGateSinks(setup.tracer), setup


# -- category 1 + 3: propagation and correlation preservation ---------------


def test_gate_span_joins_upstream_trace_and_preserves_correlation_ids():
    gate = FakeGateClient([ALLOW])
    sinks, memory = memory_sinks()
    mw = wire_middleware(gate, sinks)
    executor = StubExecutor()

    request = make_request(trace_id="t-raucle-1", traceparent=TP_1, tracestate=TS)
    out = mw.wrap_tool_call(request, executor)

    assert out == "ran"
    assert len(executor.calls) == 1
    # the gate was keyed on the existing Raucle correlation id, not the header
    assert gate.requests[0]["trace_id"] == "t-raucle-1"
    spans = memory.get_finished_spans()
    assert len(spans) == 1
    span = spans[0]
    assert span.name == "oaa.gate.decision"
    # the decision joined the caller's W3C trace
    assert format(span.context.trace_id, "032x") == TP_1_TRACE
    assert span.parent is not None
    assert format(span.parent.span_id, "016x") == TP_1_PARENT
    assert span.context.trace_state.to_header() == TS
    # and the Raucle identifiers all survived
    attrs = dict(span.attributes)
    assert attrs["oaa.trace_id"] == "t-raucle-1"
    assert attrs["oaa.call_id"] == "call-1"
    assert attrs["oaa.receipt_hash"] == "sha256:abc"
    assert attrs["oaa.verification"] == "signed"
    assert attrs["oaa.policy"] == "p.yaml"


def test_propagation_without_legacy_key_uses_w3c_trace_id():
    gate = FakeGateClient([ALLOW])
    sinks, memory = memory_sinks()
    mw = wire_middleware(gate, sinks)

    mw.wrap_tool_call(make_request(traceparent=TP_1), StubExecutor())

    assert gate.requests[0]["trace_id"] == TP_1_TRACE
    span = memory.get_finished_spans()[0]
    assert dict(span.attributes)["oaa.trace_id"] == TP_1_TRACE
    assert format(span.context.trace_id, "032x") == TP_1_TRACE


# -- category 8: independent requests never leak -------------------------------


def test_two_independent_requests_stay_in_their_own_traces():
    gate = FakeGateClient([ALLOW, ALLOW, ALLOW])
    sinks, memory = memory_sinks()
    mw = wire_middleware(gate, sinks)

    mw.wrap_tool_call(make_request("call-1", traceparent=TP_1), StubExecutor())
    mw.wrap_tool_call(make_request("call-2", traceparent=TP_2), StubExecutor())
    mw.wrap_tool_call(make_request("call-3"), StubExecutor())  # no headers at all

    finished = memory.get_finished_spans()
    assert len(finished) == 3  # one decision span per call
    by_call = {dict(s.attributes)["oaa.call_id"]: s for s in finished}
    trace_1 = format(by_call["call-1"].context.trace_id, "032x")
    trace_2 = format(by_call["call-2"].context.trace_id, "032x")
    trace_3 = format(by_call["call-3"].context.trace_id, "032x")
    assert trace_1 == TP_1_TRACE
    assert trace_2 == TP_2_TRACE
    assert trace_3 not in (TP_1_TRACE, TP_2_TRACE)  # fresh root, no inherited context
    assert by_call["call-3"].parent is None
    assert dict(by_call["call-1"].attributes)["oaa.receipt_hash"] == "sha256:abc"
    assert dict(by_call["call-2"].attributes)["oaa.call_id"] == "call-2"


# -- category 2: malformed headers, end to end ---------------------------------


def test_malformed_trace_header_e2e_decision_unchanged():
    gate = FakeGateClient([ALLOW])
    sinks, memory = memory_sinks()
    mw = wire_middleware(gate, sinks)
    executor = StubExecutor()

    out = mw.wrap_tool_call(make_request(traceparent="00-garbage-not-a-header"), executor)

    assert out == "ran"
    assert len(executor.calls) == 1
    assert gate.requests[0]["trace_id"] == "call-1"  # call-id fallback, nothing adopted
    span = memory.get_finished_spans()[0]
    assert dict(span.attributes)["oaa.trace_id"] == "call-1"
    assert span.parent is None


# -- category 9: telemetry failure never changes a decision -------------------


@pytest.mark.parametrize(
    ("decisions", "error", "fail_open", "expected_calls"),
    [
        ([ALLOW], None, False, 1),
        ([DENY], None, False, 0),
        ([], RuntimeError("gate down"), False, 0),
        ([], RuntimeError("gate down"), True, 1),
    ],
)
def test_decisions_identical_with_telemetry_up_down_or_absent(
    decisions, error, fail_open, expected_calls
):
    def run(sinks):
        gate = FakeGateClient(list(decisions), error=error)
        mw = wire_middleware(gate, sinks, fail_open=fail_open)
        executor = StubExecutor()
        out = mw.wrap_tool_call(make_request(traceparent=TP_1), executor)
        return out, len(executor.calls)

    failing_sinks_pair, setup = failing_sinks()
    outcomes = {
        "no_telemetry": run(None),
        "telemetry_down": run(failing_sinks_pair),
        "telemetry_up": run(memory_sinks()[0]),
    }
    values = list(outcomes.values())
    assert values[0] == values[1] == values[2]  # identical outcome in every mode
    assert all(calls == expected_calls for (_, calls) in values)

    exporter = setup.exporter
    assert exporter.metrics["batches"] > 0
    assert exporter.metrics["spans_dropped"] > 0  # telemetry genuinely failed
    # and its failure was visible, not silent
    assert "ConnectionRefusedError" in exporter.metrics["last_error"]
