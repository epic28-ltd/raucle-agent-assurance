# SPDX-License-Identifier: Apache-2.0
"""OpenTelemetry sinks bridging the LangGraph gate middleware onto spans (issue 111).

``OtelGateSinks`` implements both middleware callback interfaces
(``AuditSink.on_gate_event`` and ``SpanAttributeSink.set_tool_attributes``)
by duck typing: it consumes the documented gate-event mapping (see
``oaa_langgraph_adapter.middleware``) and never imports the adapter package,
so the instrumentation side stays decoupled from the adapter's dependency
surface. One instance is wired as both sinks:

    sinks = OtelGateSinks(setup.tracer)
    RaucleGateMiddleware(gate, span_sink=sinks, audit_sink=sinks,
                         trace_context_getter=w3c_trace_context_getter)

What it exports (metadata only, bounded keys, no prompts or tool arguments):

- one ``oaa.gate.decision`` span per gate event, carrying ``oaa.tool``,
  ``oaa.call_id``, ``oaa.trace_id`` (the middleware's correlation id; the
  signed ``x_gate`` trace id stays authoritative on the correlation plane),
  ``oaa.decision``, ``oaa.reason``, ``oaa.receipt_hash``,
  ``oaa.gate_latency_us``, ``oaa.adapter_latency_us``, ``oaa.agent_id``,
  ``oaa.source``, ``oaa.fail_open`` and, when the gate errored, the boolean
  ``oaa.gate_error`` (never the raw exception text, which can embed
  transport detail);
- the verification attributes the middleware attaches after an allow, set on
  that same span, which is then ended.

Parenting: when the event carries a ``traceparent`` (placed there by the
adapter's ``w3c_trace_context_getter`` and forwarded by the middleware), the
decision span is created as a child of that remote parent, canonically
re-validated here, defence in depth, and dropped when malformed, so the
enforcement decision joins the caller's trace. Without a header the span
parents onto whatever context is current, or starts a fresh trace.

Fail-independence (binding, issue 111): the middleware does not guard sink
calls, so every public method here swallows its own failures, counts them in
``metrics["sink_errors"]`` and keeps a bounded ``errors`` log. Telemetry
breakage can never propagate into the enforcement path.
"""

from __future__ import annotations

import threading
from typing import Any

from opentelemetry import trace as _otel_trace
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    TraceFlags,
    set_span_in_context,
)

from oaa_instrumentation.w3c_tracecontext import parse_traceparent, parse_tracestate

GATE_SPAN_NAME = "oaa.gate.decision"
VERIFICATION_SPAN_NAME = "oaa.tool.verification"

_MAX_RECORDED_ERRORS = 32
_ERROR_TEXT_MAX = 200


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


class OtelGateSinks:
    """Duck-typed ``AuditSink`` + ``SpanAttributeSink`` pair over one tracer.

    Open spans (an allow whose verification attributes have not arrived yet)
    are held in a bounded FIFO keyed by call id: the cap forces the oldest to
    end, so a consumer wiring only one of the two sink interfaces can never
    grow unbounded state.
    """

    def __init__(self, tracer: Any, *, max_open_spans: int = 1024) -> None:
        if max_open_spans < 1:
            raise ValueError(f"max_open_spans must be >= 1, got {max_open_spans}")
        self._tracer = tracer
        self._max_open_spans = max_open_spans
        self._lock = threading.Lock()
        self._open: dict[str, Any] = {}
        self._open_order: list[str] = []
        self.metrics: dict[str, int] = {
            "spans_started": 0,
            "spans_ended": 0,
            "sink_errors": 0,
        }
        self.errors: list[str] = []

    # -- AuditSink (duck-typed) ---------------------------------------------
    def on_gate_event(self, event: dict[str, Any]) -> None:
        """Record one gate event as a decision span; never raises."""
        try:
            self._on_event(event)
        except Exception as exc:  # telemetry must never break enforcement
            self._record_error(exc)

    # -- SpanAttributeSink (duck-typed) --------------------------------------
    def set_tool_attributes(self, call_id: str, attributes: dict[str, Any]) -> None:
        """Attach verification state to the open decision span; never raises."""
        try:
            self._set_attributes(call_id, attributes)
        except Exception as exc:  # telemetry must never break enforcement
            self._record_error(exc)

    # -- internals -------------------------------------------------------------
    def _on_event(self, event: Any) -> None:
        if not isinstance(event, dict):
            raise TypeError(f"gate event must be a mapping, got {type(event).__name__}")
        attributes = {
            "oaa.tool": str(event.get("tool", "")),
            "oaa.call_id": str(event.get("call_id", "")),
            "oaa.trace_id": str(event.get("trace_id", "")),
            "oaa.decision": str(event.get("decision", "")),
            "oaa.reason": str(event.get("reason", "")),
            "oaa.receipt_hash": str(event.get("receipt_hash") or ""),
            "oaa.gate_latency_us": _safe_int(event.get("gate_latency_us", 0)),
            "oaa.adapter_latency_us": _safe_int(event.get("adapter_latency_us", 0)),
            "oaa.agent_id": str(event.get("agent_id", "")),
            "oaa.source": str(event.get("source", "")),
            "oaa.fail_open": bool(event.get("fail_open", False)),
        }
        if event.get("error"):
            # Raw exception text can embed transport detail (URLs, endpoints);
            # the exportable fact is that the gate errored.
            attributes["oaa.gate_error"] = True
        span = self._tracer.start_span(
            GATE_SPAN_NAME, context=self._parent_context(event), attributes=attributes
        )
        with self._lock:
            self.metrics["spans_started"] += 1
        if not self._middleware_will_attach(event):
            span.end()
            with self._lock:
                self.metrics["spans_ended"] += 1
            return
        call_id = attributes["oaa.call_id"]
        if not call_id:
            span.end()
            with self._lock:
                self.metrics["spans_ended"] += 1
            return
        with self._lock:
            evicted_span = None
            if len(self._open_order) >= self._max_open_spans:
                evicted_key = self._open_order.pop(0)
                evicted_span = self._open.pop(evicted_key, None)
            self._open[call_id] = span
            self._open_order.append(call_id)
        if evicted_span is not None:
            evicted_span.end()
            with self._lock:
                self.metrics["spans_ended"] += 1

    @staticmethod
    def _middleware_will_attach(event: dict[str, Any]) -> bool:
        """Mirror of the middleware's attach conditions.

        The middleware attaches verification state after an allow with a
        receipt, and after a fail-open degraded allow; every other outcome
        ends the call, so no attach will ever follow.
        """
        if str(event.get("decision", "")) != "allow":
            return False
        if event.get("receipt_hash"):
            return True
        return bool(event.get("error")) and bool(event.get("fail_open"))

    def _parent_context(self, event: dict[str, Any]) -> Any:
        """Remote parent context from the event's W3C headers, else None.

        The getter validated these once; this re-validates canonically so a
        malformed header reaching the sink (hand-built events, future
        adapters) is dropped rather than trusted.
        """
        raw = event.get("traceparent")
        if not isinstance(raw, str) or not raw:
            return None  # ambient context: a child of whatever span is current
        parsed = parse_traceparent(raw)
        if parsed is None:
            return None
        trace_state = None
        raw_state = event.get("tracestate")
        if isinstance(raw_state, str):
            members = parse_tracestate(raw_state)  # invalid drops whole header
            if members:
                trace_state = _otel_trace.TraceState(members)
        remote = SpanContext(
            trace_id=int(parsed.trace_id, 16),
            span_id=int(parsed.parent_span_id, 16),
            is_remote=True,
            trace_flags=TraceFlags(int(parsed.trace_flags, 16)),
            trace_state=trace_state,
        )
        return set_span_in_context(NonRecordingSpan(remote))

    def _set_attributes(self, call_id: str, attributes: Any) -> None:
        key = str(call_id)
        with self._lock:
            span = self._open.pop(key, None)
            if span is not None and key in self._open_order:
                self._open_order.remove(key)
        if span is None:
            # span_sink wired without a matching open decision span (or used
            # standalone): record the verification state as its own span.
            created = self._tracer.start_span(
                VERIFICATION_SPAN_NAME, attributes=dict(attributes or {})
            )
            created.end()
            with self._lock:
                self.metrics["spans_started"] += 1
                self.metrics["spans_ended"] += 1
            return
        for attr_key, attr_value in dict(attributes or {}).items():
            span.set_attribute(str(attr_key), attr_value)
        span.end()
        with self._lock:
            self.metrics["spans_ended"] += 1

    def _record_error(self, exc: Exception) -> None:
        with self._lock:
            self.metrics["sink_errors"] += 1
            self.errors.append(f"{type(exc).__name__}: {exc}"[:_ERROR_TEXT_MAX])
            del self.errors[:-_MAX_RECORDED_ERRORS]


__all__ = [
    "GATE_SPAN_NAME",
    "VERIFICATION_SPAN_NAME",
    "OtelGateSinks",
]
