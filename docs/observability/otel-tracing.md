<!-- SPDX-License-Identifier: Apache-2.0 -->
# OpenTelemetry trace propagation and OTLP export (issue 111)

Status: shipped first slice (W3C propagation through the LangGraph gate
adapter, generic OTLP/HTTP export). See ADR-0007 for the policy decisions
and `docs/adr/0003` for the backend-adapter context. No vendor integration
(Datadog, Splunk, Elastic, CloudWatch) exists or is claimed; the export
path speaks generic OTLP over HTTP only.

## Supported propagation behaviour

- **Ingress (W3C Trace Context).** A tool-call request may carry
  `traceparent` and `tracestate` in its `state` or `runtime` mapping
  (top-level keys; teams with other shapes pass their own getter). The
  adapter's stdlib-only getter validates the header against the W3C
  grammar and adopts its trace id as the call's correlation id only when
  the runtime carried none. An existing Raucle trace id always wins: the
  gate stays keyed on the correlation id the deployment already uses.
- **Untrusted-input posture.** Externally supplied headers are
  attacker-controlled input: every dimension is bounded (traceparent 512
  chars, tracestate 5120 chars / 32 members / 256-char keys and values),
  malformed input is dropped whole, nothing raises, and no header value can
  influence an authorisation outcome. The canonical parser is
  `oaa_instrumentation.w3c_tracecontext`; the OTel sink re-validates
  headers it finds on gate events (defence in depth).
- **Enforcement decisions become spans.** `OtelGateSinks`
  (`oaa_instrumentation.otel_gate_sinks`) implements the middleware's
  audit and span-attribute callbacks. One `oaa.gate.decision` span per gate
  event carries bounded metadata only: `oaa.tool`, `oaa.call_id`,
  `oaa.trace_id` (the gate's correlation id), `oaa.decision`, `oaa.reason`,
  `oaa.receipt_hash`, `oaa.gate_latency_us`, `oaa.adapter_latency_us`,
  `oaa.agent_id`, `oaa.source`, `oaa.fail_open`, and `oaa.gate_error`
  (boolean; raw exception text is never exported). Verification attributes
  (`oaa.verification`, `oaa.receipt_hash`, `oaa.policy`) attach to the same
  span, which then ends. When the event carries a valid traceparent, the
  decision span is parented onto that remote context, so the enforcement
  decision joins the caller's trace.
- **Egress (downstream tool calls).** Inside the span that should parent
  downstream work, call
  `oaa_instrumentation.otel_export.inject_w3c_headers(headers, span)`
  to set `traceparent` (and non-empty `tracestate`) on an outgoing
  request's header mapping. A span with no valid context injects nothing
  rather than a malformed header.

## Wiring the adapter

```python
from oaa_instrumentation import OtelGateSinks, configure_tracing_from_env
from oaa_langgraph_adapter import HttpGateClient, RaucleGateMiddleware, w3c_trace_context_getter

setup = configure_tracing_from_env()  # None unless OAA_OTLP_ENDPOINT is set
if setup is not None:
    sinks = OtelGateSinks(setup.tracer)
else:
    sinks = None  # telemetry off: enforcement is unchanged either way
gate_mw = RaucleGateMiddleware(
    HttpGateClient("https://gate.example/v1/gate/check"),
    span_sink=sinks,
    audit_sink=sinks,
    trace_context_getter=w3c_trace_context_getter,
)
```

The adapter package itself never imports OpenTelemetry; the sinks live in
the instrumentation package and consume the middleware's documented event
mapping, so the callback seam stays the only propagation path.

## OTLP configuration

Telemetry is disabled unless `OAA_OTLP_ENDPOINT` is set. All variables are
validated at configuration time; a malformed value raises `ValueError`
naming the variable rather than degrading at export time.

| Variable | Default | Meaning |
|---|---|---|
| `OAA_OTLP_ENDPOINT` | unset (disabled) | OTLP/HTTP endpoint, e.g. `http://localhost:4318/v1/traces` |
| `OAA_OTEL_DISABLED` | unset | Kill switch: `1/true/yes/on` disables telemetry even when an endpoint is set |
| `OAA_OTLP_ALLOW_HTTP` | unset | `1/true` permits plain http to non-loopback hosts (opt-in) |
| `OAA_OTLP_TIMEOUT_MS` | `10000` | Export request timeout, 1 to 120000 |
| `OAA_OTLP_MAX_ATTEMPTS` | `4` | Bounded attempts per batch, 1 to 10 |
| `OAA_OTLP_BACKOFF_BASE_MS` | `1000` | Exponential backoff base (capped at 8 s), 1 to 60000 |

Endpoint scheme rules: `https` anywhere; plain `http` only for exact
loopback hosts (`localhost`, `127.0.0.1`, `::1`) without any opt-in, or for
other hosts with `OAA_OTLP_ALLOW_HTTP=1`. Credentials in the URL are
rejected.

With an endpoint set, `configure_tracing_from_env()` builds
BatchSpanProcessor to RetryingSpanExporter to RedactingSpanExporter to
OTLPSpanExporter and installs the provider globally (pass
`install_global=False` to keep it private). The same pipeline is available
piecewise via `build_export_pipeline(OtelExportConfig.from_env())`.

## Exporter failure behaviour

The stock OTLP exporter silently drops spans on connection refused. The
shipped path replaces that with bounded, visible loss (ADR-0003 P3):

- Each batch gets up to `OAA_OTLP_MAX_ATTEMPTS` attempts with exponential
  backoff (`OAA_OTLP_BACKOFF_BASE_MS` doubling per attempt, capped at 8 s;
  the worst-case stall for defaults is 7 s per batch, in the SDK's
  background export thread).
- When the bound expires the batch is dropped and counted
  (`exporter.metrics`: `batches_dropped`, `spans_dropped`, `retries`,
  `last_error`), and the SDK is told success: a telemetry outage never
  surfaces an error into enforcement code paths.
- The first successful batch after a loss streak emits one
  `oaa.telemetry.span_loss` marker span carrying
  `oaa.telemetry.lost_spans`, `oaa.telemetry.lost_batches` and the bounded
  `oaa.telemetry.last_error`, so the loss is visible in the backend, not
  only in process counters.
- `force_flush` and `shutdown` swallow delegate errors (counted in
  `flush_errors` / `shutdown_errors`); telemetry teardown can never block
  or break the caller.

## Sensitive data and redaction policy

- The PRIV-01 `RedactingSpanExporter` sits inside the retry loop, so every
  export attempt, and the marker span itself, is scrubbed through
  `packages/instrumentation/config/redaction.yaml` (config v2: AWS keys,
  bearer tokens, JWTs, private-key PEM, credential key/value pairs,
  emails, plus the entropy heuristic; no key-tier allowlist since RED-031).
  Matching values are replaced with `[REDACTED:<class>|len=<n>]`.
- The gate sinks export metadata only: identifiers, decisions, hashes and
  latencies. Prompts, tool arguments and payloads are never placed on
  these spans; raw gate exception text is reduced to a boolean.
- Trace headers carry identifiers and vendor state, not credentials: the
  canonical parser enforces charset, structure and length bounds on every
  member before anything is adopted, and the sinks re-validate.
- No unbounded-cardinality labels are emitted: span attribute keys are a
  fixed set; values are bounded strings or integers.

## Supported components and known coverage gaps

Instrumented in this slice:

- `integrations/langgraph-adapter` — W3C ingress extraction
  (`w3c_trace_context_getter`), event forwarding of the validated headers.
- `packages/instrumentation` — canonical W3C parsing/formatting, the OTLP
  export pipeline with bounded retry and visible loss, and the gate
  decision/verification spans.

Not instrumented yet (named follow-up slices on issue 111, do not read
more into the absence): the `packages/raucle-adapter` evidence plane, the
correlation service, other framework adapters (no other adapter exists
today), async LangGraph graphs (`awrap_tool_call`), vendor exporters, and
a collector-side quarantine deployment story. Trace coverage is partial by
construction and this document claims nothing beyond the list above.

## Connecting a local OpenTelemetry Collector

The generic integration point is a local collector speaking OTLP/HTTP.

1. Run one, e.g. `docker run --rm -p 4318:4318 otel/opentelemetry-collector`,
   with a receiver on `0.0.0.0:4318` (the default `otlphttp` receiver
   expects `/v1/traces`).
2. Point the suite at it: loopback http needs no opt-in.
   `export OAA_OTLP_ENDPOINT=http://localhost:4318/v1/traces`
3. Start your process. Telemetry wires itself on the first
   `configure_tracing_from_env()` call; nothing exports until then.
4. To turn telemetry off without touching deployment variables:
   `export OAA_OTEL_DISABLED=1`. Enforcement behaviour is identical either
   way, which is asserted by the test suite rather than promised.
