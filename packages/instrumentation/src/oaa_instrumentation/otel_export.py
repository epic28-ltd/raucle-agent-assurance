# SPDX-License-Identifier: Apache-2.0
"""Generic OTLP export path for Open Agent Assurance telemetry (issue 111).

Configuration is environment-only and DISABLED unless explicitly set: with
no ``OAA_OTLP_ENDPOINT`` nothing is installed, no provider is created and no
network is touched. Setting the endpoint wires a standard OpenTelemetry SDK
pipeline:

``BatchSpanProcessor -> RetryingSpanExporter -> RedactingSpanExporter ->
OTLPSpanExporter (OTLP/HTTP)``

Design invariants (binding, issue 111 and ADR-0003 P3):

- **Fail-independence.** Telemetry failure never propagates to a caller and
  never blocks or authorises anything: the retry exporter owns every
  transport error, returns ``SpanExportResult.SUCCESS`` after its bounded
  attempts expire, and counts what it dropped. The stock OTLP exporter
  silently drops spans on connection refused; this wrapper makes the loss
  visible through explicit counters plus a post-recovery marker span
  (``oaa.telemetry.span_loss``) carrying the lost counts, exported on the
  first successful batch after a loss streak.
- **Redaction before every byte on the wire.** The PRIV-01
  ``RedactingSpanExporter`` sits inside the retry loop, so every attempt
  and the marker span itself are scrubbed through the shipped redaction
  config before the delegate serialises it.
- **https posture.** ``https`` endpoints only; plain ``http`` is accepted for
  exact loopback hosts (a local collector), and for other hosts only with an
  explicit ``OAA_OTLP_ALLOW_HTTP`` opt-in.
- **Bounded knobs.** Attempts, timeout and backoff base come from validated
  environment variables; a malformed value fails configuration loudly at
  startup rather than degrading silently at export time.

This module imports OpenTelemetry at the top, mirroring
``otel_processor.py``: the OTel SDK is part of the CI dependency set, while
the W3C parsing core stays dependency-free in ``w3c_tracecontext``.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from opentelemetry import trace as _otel_trace
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    BatchSpanProcessor,
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)

from oaa_instrumentation.otel_processor import RedactingSpanExporter
from oaa_instrumentation.redaction import Redactor
from oaa_instrumentation.w3c_tracecontext import format_traceparent

#: Environment variables (OAA_ prefix, following the OAA_LF_URL family).
ENV_OTLP_ENDPOINT = "OAA_OTLP_ENDPOINT"
ENV_OTEL_DISABLED = "OAA_OTEL_DISABLED"
ENV_OTLP_ALLOW_HTTP = "OAA_OTLP_ALLOW_HTTP"
ENV_OTLP_TIMEOUT_MS = "OAA_OTLP_TIMEOUT_MS"
ENV_OTLP_MAX_ATTEMPTS = "OAA_OTLP_MAX_ATTEMPTS"
ENV_OTLP_BACKOFF_BASE_MS = "OAA_OTLP_BACKOFF_BASE_MS"

#: Marker span emitted after a loss streak recovers (visible loss, not silent).
MARKER_SPAN_NAME = "oaa.telemetry.span_loss"

_TRUE_WORDS = {"1", "true", "yes", "on"}
_FALSE_WORDS = {"0", "false", "no", "off", ""}
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

_LAST_ERROR_MAX = 200


def _parse_bool(env_name: str, raw: str) -> bool:
    word = raw.strip().lower()
    if word in _TRUE_WORDS:
        return True
    if word in _FALSE_WORDS:
        return False
    raise ValueError(f"{env_name} must be one of true/1/yes/on or false/0/no/off, got {raw!r}")


def _parse_int(env_name: str, raw: str, low: int, high: int) -> int:
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{env_name} must be an integer, got {raw!r}") from exc
    if not low <= value <= high:
        raise ValueError(f"{env_name} must be between {low} and {high}, got {value}")
    return value


def _validate_endpoint(endpoint: str, *, allow_http: bool) -> str:
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname
        _ = parsed.port  # touching .port surfaces malformed port syntax
    except ValueError as exc:
        raise ValueError(f"{ENV_OTLP_ENDPOINT} is not a valid URL: {endpoint!r}") from exc
    if parsed.scheme not in {"https", "http"} or not hostname:
        raise ValueError(
            f"{ENV_OTLP_ENDPOINT} must be an http(s) URL with a host, got {endpoint!r}"
        )
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{ENV_OTLP_ENDPOINT} must not carry credentials in the URL")
    if parsed.fragment:
        raise ValueError(f"{ENV_OTLP_ENDPOINT} must not carry a fragment")
    if parsed.scheme == "http" and hostname not in _LOOPBACK_HOSTS and not allow_http:
        raise ValueError(
            f"{ENV_OTLP_ENDPOINT} must use https (plain http is allowed only for exact "
            f"loopback hosts, or with {ENV_OTLP_ALLOW_HTTP}=1 for an explicit opt-in)"
        )
    return endpoint


@dataclass(frozen=True)
class OtelExportConfig:
    """Validated export configuration; ``enabled`` is derived, never stored."""

    endpoint: str = ""
    disabled: bool = False
    allow_http: bool = False
    timeout_seconds: float = 10.0
    max_attempts: int = 4
    backoff_base_seconds: float = 1.0
    backoff_cap_seconds: float = 8.0

    @property
    def enabled(self) -> bool:
        """Telemetry is on only when an endpoint is configured and not killed."""
        return bool(self.endpoint) and not self.disabled

    @classmethod
    def from_env(cls, env: MutableMapping[str, str] | None = None) -> OtelExportConfig:
        """Build the config from ``env`` (or ``os.environ`` when None).

        A missing/blank endpoint disables telemetry: that is the default
        posture, and the kill switch is independent so operators can force
        telemetry off without unsetting deployment variables.
        """
        source = env if env is not None else os.environ
        endpoint = str(source.get(ENV_OTLP_ENDPOINT, "")).strip()
        allow_http = _parse_bool(ENV_OTLP_ALLOW_HTTP, str(source.get(ENV_OTLP_ALLOW_HTTP, "")))
        disabled = _parse_bool(ENV_OTEL_DISABLED, str(source.get(ENV_OTEL_DISABLED, "")))
        timeout_seconds = (
            _parse_int(
                ENV_OTLP_TIMEOUT_MS, str(source.get(ENV_OTLP_TIMEOUT_MS, "10000")), 1, 120000
            )
            / 1000
        )
        max_attempts = _parse_int(
            ENV_OTLP_MAX_ATTEMPTS, str(source.get(ENV_OTLP_MAX_ATTEMPTS, "4")), 1, 10
        )
        backoff_base_seconds = (
            _parse_int(
                ENV_OTLP_BACKOFF_BASE_MS,
                str(source.get(ENV_OTLP_BACKOFF_BASE_MS, "1000")),
                1,
                60000,
            )
            / 1000
        )
        if endpoint:
            endpoint = _validate_endpoint(endpoint, allow_http=allow_http)
        return cls(
            endpoint=endpoint,
            disabled=disabled,
            allow_http=allow_http,
            timeout_seconds=timeout_seconds,
            max_attempts=max_attempts,
            backoff_base_seconds=backoff_base_seconds,
        )


class RetryingSpanExporter(SpanExporter):
    """Bounded-retry exporter wrapper with explicit, visible loss accounting.

    Retries the delegate up to ``max_attempts`` with exponential backoff
    (capped); when the bound expires the batch is DROPPED and counted, and
    ``export`` still returns ``SpanExportResult.SUCCESS``: the drop is this
    exporter's to account for, and a telemetry outage must never surface as
    an error to code whose only job is enforcement. The first successful
    export after a loss streak emits one marker span carrying the lost
    counts, so the loss is visible in the backend, not just in counters.
    """

    def __init__(
        self,
        delegate: SpanExporter,
        *,
        max_attempts: int = 4,
        backoff_base_seconds: float = 1.0,
        backoff_cap_seconds: float = 8.0,
        sleep: Callable[[float], None] = time.sleep,
        marker_span_factory: Callable[[dict[str, Any]], Any] | None = None,
    ) -> None:
        if max_attempts < 1:
            raise ValueError(f"max_attempts must be >= 1, got {max_attempts}")
        self._delegate = delegate
        self._max_attempts = max_attempts
        self._backoff_base_seconds = backoff_base_seconds
        self._backoff_cap_seconds = backoff_cap_seconds
        self._sleep = sleep
        self._marker_span_factory = marker_span_factory
        self._marker_tracer: Any = None
        self._lock = threading.Lock()
        self._pending_lost_spans = 0
        self._pending_lost_batches = 0
        self.metrics: dict[str, Any] = {
            "batches": 0,
            "export_attempts": 0,
            "retries": 0,
            "batches_dropped": 0,
            "spans_dropped": 0,
            "marker_spans_sent": 0,
            "marker_export_failures": 0,
            "flush_errors": 0,
            "shutdown_errors": 0,
            "last_error": "",
        }

    # -- SpanExporter -----------------------------------------------------
    def export(self, spans: Any) -> SpanExportResult:
        batch = list(spans)
        with self._lock:
            self.metrics["batches"] += 1
        error_text = ""
        for attempt in range(1, self._max_attempts + 1):
            try:
                result = self._delegate.export(batch)
            except Exception as exc:  # transport errors are ours, never the caller's
                result = SpanExportResult.FAILURE
                error_text = self._bounded_error(exc)
            with self._lock:
                self.metrics["export_attempts"] += 1
            if result == SpanExportResult.SUCCESS:
                return self._after_success()
            with self._lock:
                self.metrics["last_error"] = error_text or str(result)
            if attempt < self._max_attempts:
                delay = min(
                    self._backoff_base_seconds * (2 ** (attempt - 1)),
                    self._backoff_cap_seconds,
                )
                with self._lock:
                    self.metrics["retries"] += 1
                self._sleep(delay)
        with self._lock:
            self.metrics["batches_dropped"] += 1
            self.metrics["spans_dropped"] += len(batch)
            self._pending_lost_spans += len(batch)
            self._pending_lost_batches += 1
        return SpanExportResult.SUCCESS

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        """Flush is vacuous for this exporter: it never retains spans."""
        try:
            self._delegate.force_flush(timeout_millis)
        except Exception:
            with self._lock:
                self.metrics["flush_errors"] += 1
        return True

    def shutdown(self) -> None:
        try:
            self._delegate.shutdown()
        except Exception:
            with self._lock:
                self.metrics["shutdown_errors"] += 1

    # -- internals ----------------------------------------------------------
    @staticmethod
    def _bounded_error(exc: Exception) -> str:
        return f"{type(exc).__name__}: {exc}"[:_LAST_ERROR_MAX]

    def _after_success(self) -> SpanExportResult:
        with self._lock:
            lost_spans = self._pending_lost_spans
            lost_batches = self._pending_lost_batches
            last_error = str(self.metrics["last_error"])
            self._pending_lost_spans = 0
            self._pending_lost_batches = 0
        if lost_spans or lost_batches:
            self._emit_marker(lost_spans, lost_batches, last_error)
        return SpanExportResult.SUCCESS

    def _emit_marker(self, lost_spans: int, lost_batches: int, last_error: str) -> None:
        attributes = {
            "oaa.telemetry.lost_spans": lost_spans,
            "oaa.telemetry.lost_batches": lost_batches,
            "oaa.telemetry.last_error": last_error[:_LAST_ERROR_MAX],
        }
        try:
            marker = self._make_marker_span(attributes)
            result = self._delegate.export([marker])
        except Exception:
            with self._lock:
                self.metrics["marker_export_failures"] += 1
            return
        with self._lock:
            if result == SpanExportResult.SUCCESS:
                self.metrics["marker_spans_sent"] += 1
            else:
                self.metrics["marker_export_failures"] += 1

    def _make_marker_span(self, attributes: dict[str, Any]) -> Any:
        if self._marker_span_factory is not None:
            return self._marker_span_factory(attributes)
        if self._marker_tracer is None:
            # A processor-less provider: the marker span is created, ended and
            # exported directly through the delegate below, never via this
            # provider's (absent) processors.
            self._marker_tracer = TracerProvider().get_tracer("oaa_instrumentation")
        marker = self._marker_tracer.start_span(MARKER_SPAN_NAME, attributes=attributes)
        marker.end()
        return marker


@dataclass(frozen=True)
class TracingSetup:
    """One configured tracing pipeline; ``tracer`` is the entry point."""

    config: OtelExportConfig
    provider: TracerProvider
    exporter: RetryingSpanExporter
    redacting: RedactingSpanExporter
    batched: bool = True

    @property
    def tracer(self) -> Any:
        return self.provider.get_tracer("oaa_instrumentation")

    def shutdown(self) -> None:
        """Best-effort teardown; telemetry failure must never propagate."""
        try:
            self.provider.shutdown()
        except Exception:
            return


def build_export_pipeline(
    config: OtelExportConfig,
    *,
    redactor: Redactor | None = None,
    delegate: SpanExporter | None = None,
    sleep: Callable[[float], None] = time.sleep,
    batched: bool = True,
    marker_span_factory: Callable[[dict[str, Any]], Any] | None = None,
    resource_attributes: dict[str, Any] | None = None,
) -> TracingSetup:
    """Wire one export pipeline: retry -> redaction -> OTLP/HTTP delegate.

    The retry exporter wraps the redacting exporter, so scrubbing happens
    once per attempt on the delegate boundary and the marker span is scrubbed
    like any other payload. ``delegate`` overrides the OTLP exporter (tests
    inject in-memory doubles; production never should).
    """
    if not config.enabled:
        raise ValueError(
            "build_export_pipeline requires an enabled OtelExportConfig (set "
            f"{ENV_OTLP_ENDPOINT}); configure_tracing_from_env returns None when disabled"
        )
    inner: SpanExporter = (
        delegate
        if delegate is not None
        else OTLPSpanExporter(endpoint=config.endpoint, timeout=config.timeout_seconds)
    )
    redacting = RedactingSpanExporter(inner, redactor)
    retrying = RetryingSpanExporter(
        redacting,
        max_attempts=config.max_attempts,
        backoff_base_seconds=config.backoff_base_seconds,
        backoff_cap_seconds=config.backoff_cap_seconds,
        sleep=sleep,
        marker_span_factory=marker_span_factory,
    )
    resource = Resource.create(resource_attributes or {"service.name": "open-agent-assurance"})
    provider = TracerProvider(resource=resource)
    processor = BatchSpanProcessor(retrying) if batched else SimpleSpanProcessor(retrying)
    provider.add_span_processor(processor)
    return TracingSetup(
        config=config, provider=provider, exporter=retrying, redacting=redacting, batched=batched
    )


def configure_tracing_from_env(
    env: MutableMapping[str, str] | None = None,
    *,
    install_global: bool = True,
    **pipeline_kwargs: Any,
) -> TracingSetup | None:
    """Configure tracing from the environment; ``None`` when disabled.

    Disabled is the default: with no endpoint nothing is created and the
    global tracer provider is never touched. Enabled installs the pipeline's
    provider as the process-wide provider (an application-startup action);
    pass ``install_global=False`` to keep the provider private.
    """
    config = OtelExportConfig.from_env(env)
    if not config.enabled:
        return None
    setup = build_export_pipeline(config, **pipeline_kwargs)
    if install_global:
        _otel_trace.set_tracer_provider(setup.provider)
    return setup


def traceparent_from_span_context(span_context: Any) -> str:
    """Format a ``traceparent`` header for one downstream hop.

    Only valid contexts propagate: an all-zero trace or span id leaves the
    header unformattable, and this raises ``ValueError`` rather than emitting
    a malformed header that would poison the next hop.
    """
    return format_traceparent(
        format(span_context.trace_id, "032x"),
        format(span_context.span_id, "016x"),
        trace_flags=format(int(span_context.trace_flags), "02x"),
    )


def inject_w3c_headers(headers: MutableMapping[str, str], span: Any) -> None:
    """Inject ``traceparent`` (and non-empty ``tracestate``) for a downstream call.

    The egress-side counterpart of the adapter's ingress extraction: call
    with the headers mapping of an outgoing HTTP request inside the span that
    should parent the downstream work. A span with no valid context
    (all-zero ids, e.g. from an unconfigured provider) injects nothing rather
    than a malformed header.
    """
    context = span.get_span_context()
    if not context.trace_id or not context.span_id:
        return  # no valid context: inject nothing rather than a malformed header
    headers["traceparent"] = traceparent_from_span_context(context)
    trace_state = context.trace_state
    if trace_state is not None:
        state_header = trace_state.to_header()
        if state_header:
            headers["tracestate"] = state_header


__all__ = [
    "ENV_OTEL_DISABLED",
    "ENV_OTLP_ALLOW_HTTP",
    "ENV_OTLP_BACKOFF_BASE_MS",
    "ENV_OTLP_ENDPOINT",
    "ENV_OTLP_MAX_ATTEMPTS",
    "ENV_OTLP_TIMEOUT_MS",
    "MARKER_SPAN_NAME",
    "OtelExportConfig",
    "RetryingSpanExporter",
    "TracingSetup",
    "build_export_pipeline",
    "configure_tracing_from_env",
    "inject_w3c_headers",
    "traceparent_from_span_context",
]
