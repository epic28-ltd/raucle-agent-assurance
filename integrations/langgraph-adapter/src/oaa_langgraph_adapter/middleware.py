# SPDX-License-Identifier: Apache-2.0
"""The enforce-before LangGraph middleware (EPIC M K3).

``wrap_tool_call`` is the enforcement point: it receives the request and an
``execute`` callable, and vetoes by *not* calling ``execute``. Order of
operations on every tool call:

1. one gate call (``GateClient.check_tool_call``) with the correlation id
   (tool-call id, or a trace id pulled from the request context);
2. allow + receipt -> receipt/verification state attached via the span sink
   (callback interface — this package never imports OpenTelemetry), then
   ``execute(request)``;
3. deny, escalation, or any gate error under ``fail_open=False`` (default)
   -> synthetic denied tool message (or raise, per config). The tool body
   NEVER runs;
4. denial + gate latency recorded through the audit callback.

No retries happen inside the enforcement path.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol

from .gate_client import GateDecision
from .runtimes import MIDDLEWARE_BASE, ToolCallRequest

DENY_MESSAGE_PREFIX = "denied by Raucle Agent Trust gate"


class AuditSink(Protocol):
    """Callback interface for the local audit trail."""

    def on_gate_event(self, event: dict[str, Any]) -> None:
        """Receive one gate event (allow/deny/error) with latency."""
        ...  # pragma: no cover - protocol


@dataclass
class ToolCallDeniedError(RuntimeError):
    """Raised instead of a synthetic message when ``on_deny="raise"``."""

    tool: str
    call_id: str
    reason: str

    def __str__(self) -> str:
        return f"{DENY_MESSAGE_PREFIX}: {self.reason} (tool={self.tool}, call_id={self.call_id})"


@dataclass
class GateTraceContext:
    """Correlation context extracted from the request, if any."""

    trace_id: str = ""
    agent_id: str = ""
    source: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


TraceContextGetter = Callable[[ToolCallRequest], GateTraceContext]


def _trace_candidates(ctx) -> tuple:
    """Candidate trace carriers from one runtime/state object."""
    if isinstance(ctx, dict):
        return (ctx,)
    return tuple(getattr(ctx, k) for k in ("config", "metadata") if getattr(ctx, k, None))


def _trace_id_from(cand) -> str | None:
    """First trace-ish key present on one candidate carrier, else None."""
    for tk in ("trace_id", "trace-id", "oaa_trace_id", "thread_id"):
        val = cand.get(tk) if isinstance(cand, dict) else getattr(cand, tk, None)
        if isinstance(val, str) and val:
            return val
    return None


def _default_trace_context(request: ToolCallRequest) -> GateTraceContext:
    """Pull trace correlation out of the request/context if the runtime puts it there.

    Inspects ``request["runtime"]`` / ``request["state"]`` for common trace-id
    keys without depending on any concrete state schema; anything found rides
    to the gate as ``trace_id``.
    """
    for key in ("runtime", "state"):
        ctx = request.get(key)
        if not ctx:
            continue
        for cand in _trace_candidates(ctx):
            trace_id = _trace_id_from(cand)
            if trace_id is not None:
                return GateTraceContext(trace_id=trace_id)
    return GateTraceContext()


def _make_denied_message(tool: str, call_id: str, reason: str) -> Any:
    """Build a tool-role message the graph can consume as the tool result.

    Uses langchain ``ToolMessage`` when importable; otherwise a plain mapping
    with the same fields (LangGraph accepts message-shaped dicts in StateSchema
    messages channels).
    """
    content = f"{DENY_MESSAGE_PREFIX}: {reason}"
    try:  # pragma: no cover - depends on environment
        from langchain_core.messages import ToolMessage  # noqa: PLC0415 (optional dep)

        return ToolMessage(content=content, tool_call_id=call_id, name=tool)
    except Exception:
        return {"role": "tool", "content": content, "tool_call_id": call_id, "name": tool}


class RaucleGateMiddleware(MIDDLEWARE_BASE):  # type: ignore[misc,valid-type]
    """Enforce-before middleware: gate every tool call, veto on deny."""

    def __init__(
        self,
        gate: Any,
        *,
        agent_id: str = "",
        source: str = "langgraph",
        fail_open: bool = False,
        on_deny: str = "message",  # "message" | "raise"
        span_sink: Any | None = None,
        audit_sink: Any | None = None,
        trace_context_getter: TraceContextGetter | None = None,
    ) -> None:
        if on_deny not in ("message", "raise"):
            raise ValueError(f"on_deny must be 'message' or 'raise', got {on_deny!r}")
        self.gate = gate
        self.agent_id = agent_id
        self.source = source
        self.fail_open = fail_open
        self.on_deny = on_deny
        self.span_sink = span_sink
        self.audit_sink = audit_sink
        self.trace_context_getter = trace_context_getter or _default_trace_context
        self.recorded_events: list[dict[str, Any]] = []
        if audit_sink is not None:
            self.recorded_events = _RecordingList(self.audit_sink)

    # -- AgentMiddleware hook -------------------------------------------------
    def wrap_tool_call(
        self, request: ToolCallRequest, execute: Callable[[ToolCallRequest], Any]
    ) -> Any:
        call = request["tool_call"]
        call_id = call.get("id", "") or ""
        tool = call.get("name", "") or ""
        args = call.get("args", {}) or {}
        ctx = self.trace_context_getter(request)

        started = time.perf_counter()
        decision = self._safe_check(tool, args, call_id, ctx)
        elapsed_us = int((time.perf_counter() - started) * 1e6)

        event = {
            "event": "gate_decision",
            "tool": tool,
            "call_id": call_id,
            "trace_id": ctx.trace_id or call_id,
            "decision": decision.decision,
            "reason": decision.reason,
            "receipt_hash": decision.receipt_hash,
            "fail_open": self.fail_open,
            "gate_latency_us": decision.latency_us,
            "adapter_latency_us": elapsed_us,
            "agent_id": ctx.agent_id or self.agent_id,
            "source": ctx.source or self.source,
        }
        if decision.error:
            event["error"] = decision.error
        if self.audit_sink is not None:
            self.audit_sink.on_gate_event(event)

        if decision.decision == "allow" and decision.receipt_hash:
            self._attach_span_attrs(call_id, decision, event, verification="signed")
            return execute(request)

        # fail_open=True with a gate error: the call proceeds WITHOUT
        # verification state — explicitly degraded, never signed.
        if decision.decision == "allow" and decision.error and self.fail_open:
            self._attach_span_attrs(call_id, decision, event, verification="unverified")
            return execute(request)

        # Any other outcome vetoes. Notably an "allow" WITHOUT a receipt also
        # vetoes: no signed receipt means no verification state to attach, and
        # an unverified allow is worth exactly as much as a deny.
        return self._veto(tool, call_id, decision, event)

    def _attach_span_attrs(
        self, call_id: str, decision: Any, event: dict[str, Any], verification: str
    ) -> None:
        if self.span_sink is None:
            return
        attrs = {
            "oaa.gate_latency_us": event["adapter_latency_us"],
            "oaa.trace_id": event["trace_id"],
            "oaa.verification": verification,
        }
        if decision.receipt_hash:
            attrs["oaa.receipt_hash"] = decision.receipt_hash
        if decision.raw.get("policy"):
            attrs["oaa.policy"] = decision.raw["policy"]
        self.span_sink.set_tool_attributes(call_id, attrs)

    # -- internals ------------------------------------------------------------
    def _safe_check(
        self, tool: str, args: dict[str, Any], call_id: str, ctx: GateTraceContext
    ) -> Any:
        """One gate call; a gate exception becomes the fail-mode decision."""
        try:
            return self.gate.check_tool_call(
                tool=tool,
                args=dict(args),
                call_id=call_id,
                trace_id=ctx.trace_id or call_id,
                agent_id=ctx.agent_id or self.agent_id,
                source=ctx.source or self.source,
            )
        except Exception as exc:  # gate failure — resolve per fail mode
            return GateDecision(
                decision="allow" if self.fail_open else "deny",
                reason=f"gate failure: {exc}",
                error=str(exc),
            )

    def _veto(self, tool: str, call_id: str, decision: Any, event: dict[str, Any]) -> Any:
        reason = decision.reason or "deny"
        full_reason = reason
        if decision.error:
            full_reason = f"{reason} (gate error, fail_open={self.fail_open})"
        if self.on_deny == "raise":
            raise ToolCallDeniedError(tool=tool, call_id=call_id, reason=full_reason)
        return _make_denied_message(tool, call_id, full_reason)


class _RecordingList(list):  # kept minimal; audit_sink owns persistence
    def __init__(self, sink: AuditSink) -> None:
        super().__init__()
        self._sink = sink
