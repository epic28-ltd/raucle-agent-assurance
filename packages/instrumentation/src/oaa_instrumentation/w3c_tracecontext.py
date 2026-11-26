# SPDX-License-Identifier: Apache-2.0
"""W3C Trace Context parsing, validation and formatting (issue 111).

Pure standard library, deliberately free of any OpenTelemetry import so the
redaction core stays importable with the bare CI dependency set. This module
is the canonical parser for externally supplied ``traceparent`` /
``tracestate`` headers and the formatter for headers this code base produces.

Untrusted-input posture (binding, issue 111): trace headers arriving from
callers are attacker-controlled input. The parse functions therefore
*validate* against the W3C Trace Context grammar, *bound* every dimension
(total length, member count, member lengths) before doing any work, and
*drop* malformed input by returning ``None``. They never raise and never
influence an enforcement decision; the only inputs they accept on success are
32/16-char lowercase-hex identifiers.

Conformance choices (documented, pinned by tests):

- ``traceparent``: exactly four dash-separated fields for version ``00``;
  for any other version the first four fields are parsed and any remainder
  is ignored, per the W3C "future version" rule. Version ``ff`` is reserved
  and rejected. Identifiers must be lowercase hex and non-zero. Surrounding
  whitespace is trimmed; whitespace inside a field is invalid.
- ``tracestate``: keys and values follow the W3C grammar exactly. Any
  invalid member invalidates the whole header (the strictest reading;
  partial adoption of attacker content is worse than dropping it), with
  the one spec carve-out: empty and whitespace-only list members are
  allowed by the list grammar and are skipped, not fatal. Simple keys
  start with a lowercase letter; multi-tenant tenant ids may start with
  a digit. Values are printable ASCII without comma or ``=``; interior
  spaces are value characters, and edge whitespace around a member is
  OWS, never part of any value. More than 32 members, a header over
  5120 characters, or keys or values over 256 characters are dropped.
  Duplicate keys keep the first occurrence. An empty header is an empty
  member list.
- ``traceparent`` validity is independent of ``tracestate``: an invalid
  ``tracestate`` is dropped on its own, and ``tracestate`` without a valid
  ``traceparent`` is meaningless.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from typing import Any

#: Hard caps on every externally supplied header dimension.
TRACEPARENT_MAX_LENGTH = 512
TRACESTATE_MAX_LENGTH = 5120
TRACESTATE_MAX_MEMBERS = 32
TRACESTATE_MAX_KEY_LENGTH = 256
TRACESTATE_MAX_VALUE_LENGTH = 256

_VERSION_RE = re.compile(r"^[0-9a-f]{2}$")
_TRACE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_RE = re.compile(r"^[0-9a-f]{16}$")
_FLAGS_RE = re.compile(r"^[0-9a-f]{2}$")

# tracestate key (W3C key grammar): simple key (lowercase letter first,
# up to 256 chars) or multi-tenant key (tenant@system; the tenant id may
# start with a digit and carries up to 241 chars, the system id up to 14).
# The "@" separator only appears in multi-tenant keys.
_TRACESTATE_KEY_RE = re.compile(
    r"^(?:[a-z][a-z0-9_\-*/]{0,255}|[a-z0-9][a-z0-9_\-*/]{0,240}@[a-z][a-z0-9_\-*/]{0,13})$"
)
# tracestate value (W3C value = 0*255(chr) nblk-chr): printable ASCII
# except comma and "="; interior spaces allowed, final char non-blank
# (no trailing space), one character minimum.
_TRACESTATE_VALUE_RE = re.compile(
    r"^[\x20-\x2b\x2d-\x3c\x3e-\x7e]{0,255}[\x21-\x2b\x2d-\x3c\x3e-\x7e]$"
)

_OWS = " \t"


@dataclass(frozen=True)
class W3CTraceContext:
    """A validated W3C trace context (the fields the header carries)."""

    version: str
    trace_id: str
    parent_span_id: str
    trace_flags: str
    tracestate: tuple[tuple[str, str], ...] = ()


def _strip_ows(value: str) -> str:
    return value.strip(_OWS)


def _is_valid_trace_id(value: str) -> bool:
    return _TRACE_ID_RE.match(value) is not None and value != "0" * 32


def _is_valid_span_id(value: str) -> bool:
    return _SPAN_ID_RE.match(value) is not None and value != "0" * 16


def _is_valid_version(value: str) -> bool:
    return _VERSION_RE.match(value) is not None and value != "ff"


def parse_traceparent(value: Any) -> W3CTraceContext | None:
    """Parse and validate one ``traceparent`` header value.

    Returns ``None`` for anything malformed, oversized or not a string;
    never raises, so it is safe to call directly on request-supplied data.
    """
    if not isinstance(value, str):
        return None
    header = _strip_ows(value)
    if not header or len(header) > TRACEPARENT_MAX_LENGTH:
        return None
    fields = header.split("-")
    if len(fields) < 4:
        return None
    version, trace_id, parent_span_id, trace_flags = fields[0], fields[1], fields[2], fields[3]
    if version == "00" and len(fields) != 4:
        return None
    if not (
        _is_valid_version(version)
        and _is_valid_trace_id(trace_id)
        and _is_valid_span_id(parent_span_id)
        and _FLAGS_RE.match(trace_flags) is not None
    ):
        return None
    return W3CTraceContext(
        version=version,
        trace_id=trace_id,
        parent_span_id=parent_span_id,
        trace_flags=trace_flags,
    )


def parse_tracestate(value: Any) -> list[tuple[str, str]] | None:
    """Parse and validate one ``tracestate`` header value.

    Returns the member list (possibly empty), or ``None`` when the header is
    malformed, oversized or not a string. Never raises.
    """
    if not isinstance(value, str):
        return None
    header = _strip_ows(value)
    if not header:
        return []
    if len(header) > TRACESTATE_MAX_LENGTH:
        return None
    members: list[tuple[str, str]] = []
    seen: set[str] = set()
    for raw_member in header.split(","):
        member = _strip_ows(raw_member)
        if not member:
            # W3C list grammar: empty and whitespace-only list members are
            # allowed (some vendors inject whitespace after commas); skip
            # them rather than invalidating the whole header.
            continue
        key, separator, member_value = member.partition("=")
        if not separator:
            return None
        if (
            len(key) > TRACESTATE_MAX_KEY_LENGTH
            or len(member_value) > TRACESTATE_MAX_VALUE_LENGTH
            or _TRACESTATE_KEY_RE.match(key) is None
            or _TRACESTATE_VALUE_RE.match(member_value) is None
        ):
            return None
        if key in seen:
            continue
        seen.add(key)
        members.append((key, member_value))
    if len(members) > TRACESTATE_MAX_MEMBERS:
        return None
    return members


def parse_context(traceparent: Any, tracestate: Any = None) -> W3CTraceContext | None:
    """Parse a ``(traceparent, tracestate)`` pair into one context.

    A valid ``traceparent`` is required: ``tracestate`` alone carries no
    context. An invalid ``tracestate`` is dropped while the valid
    ``traceparent`` is kept.
    """
    context = parse_traceparent(traceparent)
    if context is None:
        return None
    members = parse_tracestate(tracestate)
    if members is None:
        members = []
    return replace(context, tracestate=tuple(members))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def format_traceparent(
    trace_id: str, parent_span_id: str, *, version: str = "00", trace_flags: str = "01"
) -> str:
    """Format a ``traceparent`` header from validated parts.

    Only for identifiers this code base controls (its own spans). Invalid
    input raises ``ValueError`` naming the offending field: a formatter that
    silently emitted a malformed header would poison every downstream hop.
    """
    _require(
        isinstance(trace_id, str) and _is_valid_trace_id(trace_id),
        f"invalid traceparent trace_id: {trace_id!r} (need 32 lowercase hex chars, non-zero)",
    )
    _require(
        isinstance(parent_span_id, str) and _is_valid_span_id(parent_span_id),
        f"invalid traceparent parent_span_id: {parent_span_id!r} "
        "(need 16 lowercase hex chars, non-zero)",
    )
    _require(
        isinstance(version, str) and _is_valid_version(version),
        f"invalid traceparent version: {version!r} (need 2 lowercase hex chars, not ff)",
    )
    _require(
        isinstance(trace_flags, str) and _FLAGS_RE.match(trace_flags) is not None,
        f"invalid traceparent trace_flags: {trace_flags!r} (need 2 lowercase hex chars)",
    )
    return f"{version}-{trace_id}-{parent_span_id}-{trace_flags}"


def format_tracestate(members: Sequence[tuple[str, str]]) -> str:
    """Format a ``tracestate`` header from validated members.

    Invalid members raise ``ValueError``; an empty member list formats as an
    empty string (equivalent to an absent header).
    """
    formatted: list[str] = []
    for member in members:
        _require(
            isinstance(member, tuple) and len(member) == 2,
            f"invalid tracestate member: {member!r} (need (key, value) pairs)",
        )
        key, value = member
        _require(
            isinstance(key, str)
            and len(key) <= TRACESTATE_MAX_KEY_LENGTH
            and _TRACESTATE_KEY_RE.match(key) is not None,
            f"invalid tracestate key: {key!r}",
        )
        _require(
            isinstance(value, str)
            and len(value) <= TRACESTATE_MAX_VALUE_LENGTH
            and _TRACESTATE_VALUE_RE.match(value) is not None,
            f"invalid tracestate value: {value!r}",
        )
        formatted.append(f"{key}={value}")
    return ",".join(formatted)


__all__ = [
    "TRACEPARENT_MAX_LENGTH",
    "TRACESTATE_MAX_KEY_LENGTH",
    "TRACESTATE_MAX_LENGTH",
    "TRACESTATE_MAX_MEMBERS",
    "TRACESTATE_MAX_VALUE_LENGTH",
    "W3CTraceContext",
    "format_traceparent",
    "format_tracestate",
    "parse_context",
    "parse_traceparent",
    "parse_tracestate",
]
