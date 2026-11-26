<!-- SPDX-License-Identifier: Apache-2.0 -->
# ADR-0007: OpenTelemetry trace-context propagation and OTLP export policy

Date: 26 November 2026
Status: ACCEPTED

## Context

Issue 111 asks for W3C Trace Context propagation across agent calls,
enforcement decisions and downstream tool execution, with a generic OTLP
export path. The repository had no traceparent or tracestate handling at
all, but the pieces to extend existed: the PRIV-01 redaction layers
(`RedactingSpanExporter` at the SDK, `QuarantiningSpanExporter`
collector-side), the LangGraph gate middleware with its callback-only
observability seam (span sink, audit sink, `trace_context_getter`) and the
K3 invariant that the adapter package never imports OpenTelemetry. The
ADR-0003 P3 probe had already proved the stock OTLP exporter silently drops
spans on connection refused, and set the shipped requirement: bounded
retry, explicit loss counters and a post-recovery marker span.

## Decision

1. W3C Trace Context is adopted where a caller supplies it, and it is
   untrusted input: validate against the W3C grammar, bound every dimension
   (total length, member count, member lengths), drop malformed headers
   whole, never raise on them, and never let a header influence an
   authorisation outcome.
2. The adapter keeps its no-OpenTelemetry rule. Propagation enters through
   a stdlib-only `trace_context_getter`
   (`oaa_langgraph_adapter.w3c_context.w3c_trace_context_getter`) that
   adopts a valid header's trace id only when the runtime carried none; an
   existing Raucle trace id always wins, so the gate stays keyed on the
   correlation id the deployment already uses. The middleware forwards the
   getter-extracted headers onto the gate event without parsing them:
   `traceparent` arrives fully validated, `tracestate` length-bounded raw,
   and the sink re-validates it canonically before parenting.
3. The instrumentation package owns the canonical parser
   (`w3c_tracecontext`, pure stdlib, importable with the bare CI dependency
   set) and the export path. Telemetry is disabled until
   `OAA_OTLP_ENDPOINT` is set, with an independent `OAA_OTEL_DISABLED` kill
   switch; endpoints are https-only, with plain http allowed for exact
   loopback hosts (a local collector) or behind an explicit
   `OAA_OTLP_ALLOW_HTTP` opt-in.
4. The export pipeline is BatchSpanProcessor to RetryingSpanExporter to
   RedactingSpanExporter to OTLPSpanExporter, so every export attempt and
   the loss marker itself pass through PRIV-01 redaction before any byte
   reaches the wire. The retry exporter owns all transport errors (bounded
   attempts, capped exponential backoff), reports success to the SDK once
   its bound expires, counts dropped spans and batches, and emits one
   `oaa.telemetry.span_loss` marker span on the first successful batch
   after a loss streak: loss is visible, never silent.
5. Fail-independence is structural, not a try/except afterthought:
   enforcement code paths never depend on telemetry, the sinks swallow
   their own errors into counters (the middleware does not guard them),
   and the exporter never propagates a failure upward. Gate decisions are
   identical with telemetry up, down or absent, pinned by
   `test_decisions_identical_with_telemetry_up_down_or_absent`.
6. Correlation authority is unchanged (ADR-0005): the signed `x_gate`
   trace id stays authoritative on the correlation plane; a traceparent is
   a hint that parents telemetry spans onto the caller's trace and never
   authenticates anything.

## Consequences

- The gate decision span joins the caller's W3C trace when the header is
  valid and starts a fresh trace otherwise; the correlation id the gate was
  keyed on rides the span as `oaa.trace_id` either way.
- Raw gate exception text is not exported (it can embed transport detail
  such as endpoints); only the boolean fact `oaa.gate_error` crosses.
- Vendor backends (Datadog, Splunk, Elastic, CloudWatch) are out of scope
  by design: the export path is generic OTLP/HTTP, and a local
  OpenTelemetry Collector is the documented integration point.
- Instrumentation today covers the LangGraph adapter seam and the
  instrumentation package; the raucle-adapter package and the correlation
  service do not emit OTel spans yet. Those are named follow-up slices on
  issue 111, not claims of end-to-end coverage.

## Related

- ADR-0003 (backend adapter; P3 outage invariant)
- ADR-0005 (gate identity correlation; trace ids are hints)
- docs/observability/otel-tracing.md (operator guide)
- docs/spikes/K3-adapter-findings.md, docs/spikes/OBS-01-findings.md
