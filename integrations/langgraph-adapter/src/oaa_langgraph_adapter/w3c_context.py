# SPDX-License-Identifier: Apache-2.0
"""W3C Trace Context extraction for the gate middleware (issue 111).

This module is the adapter's propagation seam and stays deliberately
standard-library only: the package rule from the K3 spike holds, this
package never imports OpenTelemetry, and trace context reaches telemetry
only through the ``trace_context_getter`` callback plus the raw header
strings it places in ``GateTraceContext.extra`` (the middleware forwards
them onto the gate event; an OTel-side sink in the instrumentation
package does the actual span parenting).

Validation here is a strict subset of the canonical parser in
``oaa_instrumentation.w3c_tracecontext``: the adapter accepts only exact
four-field traceparent headers with lowercase-hex, non-zero identifiers
and any version except the reserved ``ff``. Everything the adapter
accepts, the canonical parser accepts too; the adapter may be stricter.
``tracestate`` is passed through raw after a length bound only, because
member-level validation is consumer-side work: the OTel sink re-validates
it canonically and drops it when malformed.

Untrusted-input posture (binding, issue 111): request-supplied headers are
attacker-controlled. The getter validates, bounds and drops malformed
values, never raises, and never influences the enforcement decision; it
also preserves the existing Raucle correlation identifiers, so a valid
W3C header never overwrites a trace id the runtime already carried.
"""

from __future__ import annotations

import re
from typing import Any

from .middleware import GateTraceContext, _default_trace_context, _trace_candidates
from .runtimes import ToolCallRequest

#: Bounds mirroring the canonical parser (oaa_instrumentation.w3c_tracecontext).
TRACEPARENT_MAX_LENGTH = 512
TRACESTATE_MAX_LENGTH = 5120

_TRACEPARENT_RE = re.compile(r"^([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")
_OWS = " \t"


def _read_string(candidate: Any, key: str) -> str | None:
    """Read ``key`` off one candidate carrier as a string, else None."""
    value = candidate.get(key) if isinstance(candidate, dict) else getattr(candidate, key, None)
    return value if isinstance(value, str) else None


def _find_headers(request: Any) -> tuple[str, str | None] | None:
    """First (traceparent, tracestate?) pair found in runtime/state carriers."""
    for carrier_key in ("runtime", "state"):
        carrier = request.get(carrier_key)
        if not carrier:
            continue
        for candidate in _trace_candidates(carrier):
            traceparent = _read_string(candidate, "traceparent")
            if traceparent is not None:
                return traceparent, _read_string(candidate, "tracestate")
    return None


def validated_trace_id(traceparent: str) -> str | None:
    """The W3C trace id of a well-formed traceparent, else None (drop)."""
    header = traceparent.strip(_OWS)
    if not header or len(header) > TRACEPARENT_MAX_LENGTH:
        return None
    match = _TRACEPARENT_RE.match(header)
    if match is None:
        return None
    version, trace_id, parent_id, _flags = match.groups()
    if version == "ff" or trace_id == "0" * 32 or parent_id == "0" * 16:
        return None
    return trace_id


def _extract(request: Any) -> GateTraceContext:
    fallback = _default_trace_context(request)
    headers = _find_headers(request)
    if headers is None:
        return fallback
    traceparent, tracestate = headers
    trace_id = validated_trace_id(traceparent)
    if trace_id is None:
        # Malformed header: dropped whole, existing identifiers untouched.
        return fallback
    extra: dict[str, Any] = {"traceparent": traceparent.strip(_OWS)}
    if tracestate is not None:
        stripped = tracestate.strip(_OWS)
        if stripped and len(stripped) <= TRACESTATE_MAX_LENGTH:
            extra["tracestate"] = stripped
    if fallback.trace_id:
        # Preserve the existing Raucle correlation id; the raw header still
        # rides extra so consumer-side sinks can join the upstream trace.
        return GateTraceContext(
            trace_id=fallback.trace_id,
            agent_id=fallback.agent_id,
            source=fallback.source,
            extra=extra,
        )
    return GateTraceContext(trace_id=trace_id, extra=extra)


def w3c_trace_context_getter(request: ToolCallRequest) -> GateTraceContext:
    """Extract trace correlation from W3C headers in the request (issue 111).

    Never raises: any unexpected request shape degrades to an empty context,
    which the middleware already treats as "no correlation id, use call_id".
    Never parses tool arguments or payloads, and never influences the gate
    decision; it only picks the correlation id and forwards raw headers.
    """
    try:
        return _extract(request)
    except Exception:
        return GateTraceContext()


__all__ = ["TRACEPARENT_MAX_LENGTH", "TRACESTATE_MAX_LENGTH", "w3c_trace_context_getter"]
