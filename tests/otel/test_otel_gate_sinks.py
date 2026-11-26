# SPDX-License-Identifier: Apache-2.0
"""OTel gate sink tests (issue 111): gate events become spans, verification
state attaches, every sink failure is swallowed, and upstream W3C context
parents the decision span onto the caller's trace.
"""

from __future__ import annotations

from oaa_instrumentation.otel_gate_sinks import OtelGateSinks
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

UPSTREAM_TP = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
UPSTREAM_TRACE_ID = "4bf92f3577b34da6a3ce929d0e0e4736"
UPSTREAM_PARENT_ID = "00f067aa0ba902b7"
UPSTREAM_TS = "congo=t61rcWkgMzE,rojo=00f067aa0ba902b7"


def make_sinks(max_open_spans: int = 1024) -> tuple[OtelGateSinks, InMemorySpanExporter]:
    memory = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(memory))
    tracer = provider.get_tracer("oaa.test")
    return OtelGateSinks(tracer, max_open_spans=max_open_spans), memory


def gate_event(**overrides) -> dict:
    event = {
        "event": "gate_decision",
        "tool": "read_file",
        "call_id": "call-1",
        "trace_id": "t-raucle-1",
        "decision": "allow",
        "reason": "policy: read allowed",
        "receipt_hash": "sha256:abc",
        "fail_open": False,
        "gate_latency_us": 150,
        "adapter_latency_us": 200,
        "agent_id": "agent:t",
        "source": "langgraph",
    }
    event.update(overrides)
    return event


def test_allow_with_receipt_creates_span_then_verification_ends_it() -> None:
    sinks, memory = make_sinks()
    sinks.on_gate_event(gate_event())
    assert len(memory.get_finished_spans()) == 0  # open, waiting for verification
    sinks.set_tool_attributes(
        "call-1", {"oaa.verification": "signed", "oaa.receipt_hash": "sha256:abc"}
    )
    spans = memory.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "oaa.gate.decision"
    attrs = dict(spans[0].attributes)
    assert attrs["oaa.decision"] == "allow"
    assert attrs["oaa.verification"] == "signed"
    assert attrs["oaa.receipt_hash"] == "sha256:abc"
    assert attrs["oaa.trace_id"] == "t-raucle-1"
    assert attrs["oaa.call_id"] == "call-1"
    assert attrs["oaa.tool"] == "read_file"
    assert attrs["oaa.reason"] == "policy: read allowed"
    assert attrs["oaa.gate_latency_us"] == 150
    assert attrs["oaa.adapter_latency_us"] == 200
    assert attrs["oaa.agent_id"] == "agent:t"
    assert attrs["oaa.source"] == "langgraph"
    assert attrs["oaa.fail_open"] is False


def test_deny_ends_the_span_immediately() -> None:
    sinks, memory = make_sinks()
    sinks.on_gate_event(gate_event(decision="deny", receipt_hash=None, reason="policy: no rule"))
    spans = memory.get_finished_spans()
    assert len(spans) == 1
    attrs = dict(spans[0].attributes)
    assert attrs["oaa.decision"] == "deny"
    assert "oaa.verification" not in attrs


def test_unverified_allow_that_will_veto_ends_immediately() -> None:
    # allow without a receipt and without a fail-open error vetoes in the
    # middleware; no verification attach will ever arrive for it.
    sinks, memory = make_sinks()
    sinks.on_gate_event(gate_event(receipt_hash=None))
    assert len(memory.get_finished_spans()) == 1


def test_fail_open_unverified_allow_stays_open_for_attach() -> None:
    sinks, memory = make_sinks()
    sinks.on_gate_event(
        gate_event(receipt_hash=None, error="gate unreachable: boom", fail_open=True)
    )
    assert len(memory.get_finished_spans()) == 0
    sinks.set_tool_attributes("call-1", {"oaa.verification": "unverified"})
    assert len(memory.get_finished_spans()) == 1


def test_gate_error_exports_flag_not_raw_text() -> None:
    sinks, memory = make_sinks()
    raw_error = "gate unreachable: GET https://gate.example/x?token=supersecretvalue failed"
    sinks.on_gate_event(
        gate_event(decision="deny", receipt_hash=None, error=raw_error, fail_open=False)
    )
    spans = memory.get_finished_spans()
    attrs = dict(spans[0].attributes)
    assert attrs["oaa.gate_error"] is True
    assert "supersecretvalue" not in str(attrs)
    assert raw_error not in str(attrs)


def test_span_joins_upstream_trace_from_event_headers() -> None:
    sinks, memory = make_sinks()
    sinks.on_gate_event(gate_event(traceparent=UPSTREAM_TP, tracestate=UPSTREAM_TS))
    sinks.set_tool_attributes("call-1", {"oaa.verification": "signed"})
    span = memory.get_finished_spans()[0]
    assert format(span.context.trace_id, "032x") == UPSTREAM_TRACE_ID
    assert span.parent is not None
    assert format(span.parent.span_id, "016x") == UPSTREAM_PARENT_ID
    assert span.parent.is_remote is True
    assert span.context.trace_state.to_header() == UPSTREAM_TS


def test_malformed_traceparent_in_event_falls_back_to_root() -> None:
    # The getter validates, but the sink re-validates canonically (defence in
    # depth): a malformed header must never parent a span or raise.
    sinks, memory = make_sinks()
    sinks.on_gate_event(gate_event(traceparent="00-bad-header"))
    sinks.set_tool_attributes("call-1", {"oaa.verification": "signed"})
    span = memory.get_finished_spans()[0]
    assert format(span.context.trace_id, "032x") != "00-bad-header"
    assert span.parent is None


def test_open_span_bound_forces_end_fifo() -> None:
    sinks, memory = make_sinks(max_open_spans=2)
    for index in range(3):
        sinks.on_gate_event(gate_event(call_id=f"call-{index}"))
    # cap 2: the oldest was force-ended, one is still open
    assert len(memory.get_finished_spans()) == 1
    sinks.set_tool_attributes("call-2", {"oaa.verification": "signed"})
    assert len(memory.get_finished_spans()) == 2


def test_set_tool_attributes_without_open_span_records_verification() -> None:
    sinks, memory = make_sinks()
    sinks.set_tool_attributes("call-9", {"oaa.verification": "signed"})
    spans = memory.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "oaa.tool.verification"
    assert dict(spans[0].attributes)["oaa.verification"] == "signed"


class BrokenTracer:
    def start_span(self, *args, **kwargs):
        raise RuntimeError("tracer exploded")


def test_sink_never_raises_on_tracer_failure() -> None:
    sinks = OtelGateSinks(BrokenTracer())  # type: ignore[arg-type]
    sinks.on_gate_event(gate_event())
    sinks.set_tool_attributes("call-1", {"oaa.verification": "signed"})
    sinks.on_gate_event(gate_event(call_id="call-2", decision="deny", receipt_hash=None))
    assert sinks.metrics["sink_errors"] == 3
    assert sinks.errors
    assert "tracer exploded" in sinks.errors[0]


def test_non_mapping_event_is_counted_not_raised() -> None:
    sinks, _ = make_sinks()
    sinks.on_gate_event(None)  # type: ignore[arg-type]
    sinks.on_gate_event(["not", "a", "dict"])  # type: ignore[arg-type]
    assert sinks.metrics["sink_errors"] == 2
