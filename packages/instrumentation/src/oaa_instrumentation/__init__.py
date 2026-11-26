# SPDX-License-Identifier: Apache-2.0
"""Open Agent Assurance PRIV-01 instrumentation: SDK-side redaction and
collector-side defence-in-depth over span attributes, plus the OTel exporter
wrappers that install both layers, the W3C trace-context core and the
generic OTLP export path with OTel sinks for the gate middleware.

Modules:
- :mod:`oaa_instrumentation.redaction`: deterministic, versioned redactor
  (``[REDACTED:<class>|len=<n>]`` replacement, NO key-tier metadata
  exemption since RED-031, entropy heuristic) and the collector batch
  scan/quarantine.
- :mod:`oaa_instrumentation.otel_processor`: ``RedactingSpanExporter``
  (redaction at the SDK, before export) and ``QuarantiningSpanExporter``
  (re-scan just before export; violations counted, never logged with content).
- :mod:`oaa_instrumentation.w3c_tracecontext`: pure-stdlib parse/validate/
  format for ``traceparent``/``tracestate``: untrusted headers are bounded,
  validated and dropped when malformed; never parsed into a decision.
- :mod:`oaa_instrumentation.otel_export`: env-configured, disabled-by-default
  OTLP/HTTP pipeline: bounded retry, explicit loss counters, post-recovery
  marker span, PRIV-01 redaction inside the retry loop, plus the egress
  helpers that format downstream trace headers.
- :mod:`oaa_instrumentation.otel_gate_sinks`: duck-typed sinks turning the
  LangGraph gate middleware's audit/span callbacks into decision spans
  parented onto the caller's W3C trace.
"""

from oaa_instrumentation.otel_export import (
    ENV_OTLP_ENDPOINT,
    MARKER_SPAN_NAME,
    OtelExportConfig,
    RetryingSpanExporter,
    TracingSetup,
    build_export_pipeline,
    configure_tracing_from_env,
    inject_w3c_headers,
    traceparent_from_span_context,
)
from oaa_instrumentation.otel_gate_sinks import (
    GATE_SPAN_NAME,
    VERIFICATION_SPAN_NAME,
    OtelGateSinks,
)
from oaa_instrumentation.otel_processor import (
    QuarantiningSpanExporter,
    RedactingSpanExporter,
    span_attribute_map,
)
from oaa_instrumentation.redaction import (
    REDACTION_CONFIG_VERSION,
    RedactionConfig,
    RedactionViolation,
    Redactor,
    ScanReport,
    quarantine,
    scan_batch,
)
from oaa_instrumentation.w3c_tracecontext import (
    W3CTraceContext,
    format_traceparent,
    format_tracestate,
    parse_context,
    parse_traceparent,
    parse_tracestate,
)

__all__ = [
    "ENV_OTLP_ENDPOINT",
    "GATE_SPAN_NAME",
    "MARKER_SPAN_NAME",
    "REDACTION_CONFIG_VERSION",
    "VERIFICATION_SPAN_NAME",
    "OtelExportConfig",
    "OtelGateSinks",
    "QuarantiningSpanExporter",
    "RedactingSpanExporter",
    "RedactionConfig",
    "RedactionViolation",
    "Redactor",
    "RetryingSpanExporter",
    "ScanReport",
    "TracingSetup",
    "W3CTraceContext",
    "build_export_pipeline",
    "configure_tracing_from_env",
    "format_traceparent",
    "format_tracestate",
    "inject_w3c_headers",
    "parse_context",
    "parse_traceparent",
    "parse_tracestate",
    "quarantine",
    "scan_batch",
    "span_attribute_map",
    "traceparent_from_span_context",
]
__version__ = "0.0.1.dev0"
