# instrumentation — PRIV-01 redaction and OTel trace export (issue 111)

SDK-side span-attribute redaction plus collector-side defence-in-depth for
Open Agent Assurance (story PRIV-01: sensitive content must not persist in
the normal trace store), and the issue-111 surface: W3C Trace Context
parsing, the generic OTLP export path and the gate-middleware OTel sinks.

## Layout

- `src/oaa_instrumentation/redaction.py` — the deterministic redaction core:
  versioned pattern config (`config/redaction.yaml`, `config_version: 2`)
  matching AWS access keys, bearer tokens, JWTs, private-key PEM blocks,
  credential key/value pairings and emails; plus a high-entropy heuristic
  (Shannon entropy per char ≥ 4.0, length ≥ 20, base64-ish charset only).
  Matching values are replaced with `[REDACTED:<class>|len=<n>]` — the class
  tag and the original length, nothing else. There is no key-tier allowlist
  (RED-031): every non-empty value is scanned regardless of its key.
- `src/oaa_instrumentation/otel_processor.py` — OTel exporter wrappers:
  `RedactingSpanExporter` (scrub at the SDK, before export) and
  `QuarantiningSpanExporter` (re-scan the batch immediately before export;
  flagged spans are held back and counted — violations are counted, never
  logged with the secret).
- `src/oaa_instrumentation/w3c_tracecontext.py` — pure-stdlib W3C Trace
  Context parse/validate/format for `traceparent`/`tracestate`. Externally
  supplied headers are untrusted input: bounded, validated, dropped whole
  when malformed, never parsed into a decision. Importable with the bare CI
  dependency set (no OpenTelemetry import).
- `src/oaa_instrumentation/otel_export.py` — the generic, env-configured
  OTLP/HTTP export path: disabled until `OAA_OTLP_ENDPOINT` is set,
  bounded retry with explicit loss counters, a post-recovery marker span,
  PRIV-01 redaction inside the retry loop, and the egress helpers
  (`traceparent_from_span_context`, `inject_w3c_headers`).
- `src/oaa_instrumentation/otel_gate_sinks.py` — `OtelGateSinks`, the
  duck-typed audit/span sinks that turn the LangGraph gate middleware's
  callbacks into `oaa.gate.decision` spans parented onto the caller's W3C
  trace. Metadata only; every failure is swallowed into counters.
- `config/redaction.yaml` — the versioned pattern config.

See `docs/observability/otel-tracing.md` for the operator guide and
`docs/adr/0007-otel-trace-context.md` for the policy decisions.

## Guarantees

- Deterministic: same input batch → same scrubbed output and same violation
  set; no wall-clock, no RNG.
- Violation records carry `pattern_id`, `privacy_class`, `attr_key` and the
  matched length only — never the matched value.
- A content-hash of a secret is NOT anonymisation; only the length prefix is
  retained.
- Detection is pattern- plus entropy-based, not semantic (see
  `docs/spikes/PRIV-01-findings.md` for proven limits).
- Telemetry failure is fail-independent: the retry exporter owns transport
  errors, returns success to the SDK once its bound expires, and counts
  what it dropped; sinks swallow their own errors. Enforcement decisions
  are identical with telemetry up, down or absent (pinned by
  `tests/otel/test_propagation_end_to_end.py`).
