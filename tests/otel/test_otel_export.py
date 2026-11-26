# SPDX-License-Identifier: Apache-2.0
"""OTLP export path tests (issue 111): env config, bounded retry, visible
loss, post-recovery marker, redaction order, disabled telemetry.

All network is faked: delegates are in-memory scripted SpanExporter doubles,
the sleeper is injected, no test touches a socket. Categories 4, 5, 6 and 7
from the issue map live here alongside the config contract.
"""

from __future__ import annotations

import pytest
from oaa_instrumentation.otel_export import (
    ENV_OTEL_DISABLED,
    ENV_OTLP_ALLOW_HTTP,
    ENV_OTLP_BACKOFF_BASE_MS,
    ENV_OTLP_ENDPOINT,
    ENV_OTLP_MAX_ATTEMPTS,
    ENV_OTLP_TIMEOUT_MS,
    MARKER_SPAN_NAME,
    OtelExportConfig,
    RetryingSpanExporter,
    build_export_pipeline,
    configure_tracing_from_env,
    inject_w3c_headers,
    traceparent_from_span_context,
)
from oaa_instrumentation.w3c_tracecontext import parse_traceparent
from opentelemetry import trace as otel_trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult
from opentelemetry.trace import NonRecordingSpan, SpanContext

AWS_KEY_FIXTURE = "AKIAIOSFODNN7EXAMPLE"
AWS_KEY_TOKEN = "[REDACTED:aws_access_key|len=20]"


class StubSpan:
    """Minimal stand-in the retry exporter passes through untouched."""

    def __init__(self, name: str = "stub") -> None:
        self.name = name


class ScriptedDelegate(SpanExporter):
    """Delegate exporter with a scripted outcome per export call.

    Script entries are exceptions (raised) or SpanExportResult values
    (returned); an exhausted script returns SUCCESS. Every call is recorded.
    """

    def __init__(self, script=()):
        self.script = list(script)
        self.span_calls: list[list] = []
        self.flush_calls: list[int] = []
        self.shutdown_calls: list[bool] = []
        self.flush_error: Exception | None = None
        self.shutdown_error: Exception | None = None

    def export(self, spans) -> SpanExportResult:
        self.span_calls.append(list(spans))
        step = self.script.pop(0) if self.script else SpanExportResult.SUCCESS
        if isinstance(step, Exception):
            raise step
        return step

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        self.flush_calls.append(timeout_millis)
        if self.flush_error is not None:
            raise self.flush_error
        return True

    def shutdown(self) -> None:
        self.shutdown_calls.append(True)
        if self.shutdown_error is not None:
            raise self.shutdown_error


class SleepRecorder:
    def __init__(self) -> None:
        self.delays: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


# -- config from environment --------------------------------------------------


def test_config_empty_env_disables_telemetry() -> None:
    config = OtelExportConfig.from_env({})
    assert config.enabled is False
    assert config.endpoint == ""


def test_config_endpoint_enables_with_defaults() -> None:
    config = OtelExportConfig.from_env({ENV_OTLP_ENDPOINT: "https://collector.example/v1/traces"})
    assert config.enabled is True
    assert config.endpoint == "https://collector.example/v1/traces"
    assert config.allow_http is False
    assert config.timeout_seconds == 10.0
    assert config.max_attempts == 4
    assert config.backoff_base_seconds == 1.0


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "TRUE", "Yes"])
def test_config_disabled_kill_switch(value: str) -> None:
    config = OtelExportConfig.from_env(
        {ENV_OTLP_ENDPOINT: "https://collector.example", ENV_OTEL_DISABLED: value}
    )
    assert config.enabled is False


@pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
def test_config_disabled_kill_switch_off_keeps_enabled(value: str) -> None:
    config = OtelExportConfig.from_env(
        {ENV_OTLP_ENDPOINT: "https://collector.example", ENV_OTEL_DISABLED: value}
    )
    assert config.enabled is True


def test_config_disabled_rejects_unknown_vocabulary() -> None:
    with pytest.raises(ValueError, match=ENV_OTEL_DISABLED):
        OtelExportConfig.from_env(
            {ENV_OTLP_ENDPOINT: "https://collector.example", ENV_OTEL_DISABLED: "maybe"}
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://collector.example/v1/traces",
        "http://localhost:4318/v1/traces",
        "http://127.0.0.1:4318/v1/traces",
        "http://[::1]:4318/v1/traces",
    ],
)
def test_config_accepts_https_and_loopback_http(endpoint: str) -> None:
    assert OtelExportConfig.from_env({ENV_OTLP_ENDPOINT: endpoint}).enabled is True


def test_config_plain_http_non_loopback_requires_opt_in() -> None:
    env = {ENV_OTLP_ENDPOINT: "http://collector.internal:4318/v1/traces"}
    with pytest.raises(ValueError, match="https"):
        OtelExportConfig.from_env(env)
    env[ENV_OTLP_ALLOW_HTTP] = "1"
    assert OtelExportConfig.from_env(env).enabled is True


@pytest.mark.parametrize(
    "endpoint",
    [
        "ftp://collector.example",
        "not a url",
        "https://",
        "http://user:pw@collector.example",
        "https://collector.example/#frag",
    ],
)
def test_config_rejects_bad_endpoints(endpoint: str) -> None:
    with pytest.raises(ValueError, match=ENV_OTLP_ENDPOINT):
        OtelExportConfig.from_env({ENV_OTLP_ENDPOINT: endpoint})


def test_config_numeric_env_vars_validated() -> None:
    base = {ENV_OTLP_ENDPOINT: "https://collector.example"}
    with pytest.raises(ValueError, match=ENV_OTLP_TIMEOUT_MS):
        OtelExportConfig.from_env({**base, ENV_OTLP_TIMEOUT_MS: "abc"})
    with pytest.raises(ValueError, match=ENV_OTLP_TIMEOUT_MS):
        OtelExportConfig.from_env({**base, ENV_OTLP_TIMEOUT_MS: "0"})
    with pytest.raises(ValueError, match=ENV_OTLP_TIMEOUT_MS):
        OtelExportConfig.from_env({**base, ENV_OTLP_TIMEOUT_MS: "99000000"})
    with pytest.raises(ValueError, match=ENV_OTLP_MAX_ATTEMPTS):
        OtelExportConfig.from_env({**base, ENV_OTLP_MAX_ATTEMPTS: "0"})
    with pytest.raises(ValueError, match=ENV_OTLP_MAX_ATTEMPTS):
        OtelExportConfig.from_env({**base, ENV_OTLP_MAX_ATTEMPTS: "11"})
    with pytest.raises(ValueError, match=ENV_OTLP_BACKOFF_BASE_MS):
        OtelExportConfig.from_env({**base, ENV_OTLP_BACKOFF_BASE_MS: "nope"})
    ok = OtelExportConfig.from_env(
        {
            **base,
            ENV_OTLP_TIMEOUT_MS: "2000",
            ENV_OTLP_MAX_ATTEMPTS: "3",
            ENV_OTLP_BACKOFF_BASE_MS: "250",
        }
    )
    assert ok.timeout_seconds == 2.0
    assert ok.max_attempts == 3
    assert ok.backoff_base_seconds == 0.25


# -- RetryingSpanExporter: bounded retry and visible loss ---------------------


def test_exporter_unavailable_drops_visibly_and_never_propagates() -> None:
    delegate = ScriptedDelegate([ConnectionRefusedError("connection refused")] * 4)
    sleeps = SleepRecorder()
    exporter = RetryingSpanExporter(
        delegate, backoff_base_seconds=1.0, backoff_cap_seconds=8.0, sleep=sleeps
    )
    result = exporter.export([StubSpan("a"), StubSpan("b")])

    assert result == SpanExportResult.SUCCESS  # loss is ours to account, never the caller's
    assert exporter.metrics["spans_dropped"] == 2
    assert exporter.metrics["batches_dropped"] == 1
    assert exporter.metrics["export_attempts"] == 4
    assert exporter.metrics["retries"] == 3
    assert sleeps.delays == [1.0, 2.0, 4.0]
    assert "ConnectionRefusedError" in exporter.metrics["last_error"]
    assert len(delegate.span_calls) == 4


def test_exporter_timeout_failure_is_bounded() -> None:
    delegate = ScriptedDelegate([TimeoutError("timed out")] * 4)
    exporter = RetryingSpanExporter(delegate, sleep=SleepRecorder())
    result = exporter.export([StubSpan("a")])

    assert result == SpanExportResult.SUCCESS
    assert exporter.metrics["spans_dropped"] == 1
    assert "TimeoutError" in exporter.metrics["last_error"]


def test_exporter_failure_result_retried_like_an_exception() -> None:
    delegate = ScriptedDelegate([SpanExportResult.FAILURE] * 4)
    exporter = RetryingSpanExporter(delegate, sleep=SleepRecorder())
    assert exporter.export([StubSpan("a")]) == SpanExportResult.SUCCESS
    assert exporter.metrics["spans_dropped"] == 1
    assert exporter.metrics["export_attempts"] == 4


def test_exporter_succeeds_within_bound_records_no_loss() -> None:
    delegate = ScriptedDelegate([OSError("flap"), SpanExportResult.SUCCESS])
    exporter = RetryingSpanExporter(delegate, sleep=SleepRecorder())
    assert exporter.export([StubSpan("a")]) == SpanExportResult.SUCCESS
    assert exporter.metrics["spans_dropped"] == 0
    assert exporter.metrics["retries"] == 1
    assert exporter.metrics["marker_spans_sent"] == 0


def test_recovery_emits_post_loss_marker_span() -> None:
    delegate = ScriptedDelegate([ConnectionRefusedError()] * 4 + [SpanExportResult.SUCCESS] * 4)
    sleeps = SleepRecorder()
    exporter = RetryingSpanExporter(delegate, sleep=sleeps)

    assert exporter.export([StubSpan("lost")]) == SpanExportResult.SUCCESS
    assert exporter.metrics["spans_dropped"] == 1
    assert exporter.metrics["marker_spans_sent"] == 0

    assert exporter.export([StubSpan("recovered")]) == SpanExportResult.SUCCESS
    assert exporter.metrics["marker_spans_sent"] == 1
    marker_call = delegate.span_calls[5]  # batch1 x4, batch2 x1, then the marker
    assert len(marker_call) == 1
    marker = marker_call[0]
    assert marker.name == MARKER_SPAN_NAME
    attrs = dict(marker.attributes)
    assert attrs["oaa.telemetry.lost_spans"] == 1
    assert attrs["oaa.telemetry.lost_batches"] == 1
    assert "ConnectionRefusedError" in attrs["oaa.telemetry.last_error"]

    # A clean streak after recovery emits no second marker.
    assert exporter.export([StubSpan("clean")]) == SpanExportResult.SUCCESS
    assert exporter.metrics["marker_spans_sent"] == 1


def test_marker_export_failure_is_counted_not_raised() -> None:
    delegate = ScriptedDelegate(
        [ConnectionRefusedError()] * 4
        + [SpanExportResult.SUCCESS]
        + [OSError("marker flap")]
        + [SpanExportResult.SUCCESS]
    )
    exporter = RetryingSpanExporter(delegate, sleep=SleepRecorder())

    assert exporter.export([StubSpan("lost")]) == SpanExportResult.SUCCESS
    assert exporter.export([StubSpan("recovered")]) == SpanExportResult.SUCCESS
    assert exporter.metrics["marker_export_failures"] == 1
    # the pending loss is consumed by the marker attempt either way
    assert exporter.export([StubSpan("clean")]) == SpanExportResult.SUCCESS
    assert exporter.metrics["marker_spans_sent"] == 0


def test_flush_and_shutdown_swallow_delegate_errors() -> None:
    delegate = ScriptedDelegate()
    delegate.flush_error = OSError("flush broken")
    delegate.shutdown_error = OSError("shutdown broken")
    exporter = RetryingSpanExporter(delegate)
    assert exporter.force_flush(123) is True
    exporter.shutdown()
    assert delegate.flush_calls == [123]
    assert delegate.shutdown_calls == [True]

    healthy = ScriptedDelegate()
    healthy_exporter = RetryingSpanExporter(healthy)
    assert healthy_exporter.force_flush() is True
    healthy_exporter.shutdown()
    assert healthy.shutdown_calls == [True]


def test_empty_batch_delegates_once_without_retry() -> None:
    delegate = ScriptedDelegate([SpanExportResult.SUCCESS])
    exporter = RetryingSpanExporter(delegate, sleep=SleepRecorder())
    assert exporter.export([]) == SpanExportResult.SUCCESS
    assert len(delegate.span_calls) == 1
    assert exporter.metrics["retries"] == 0


# -- pipeline build and configuration ------------------------------------------


def test_configure_from_env_disabled_returns_none_and_touches_no_globals(
    monkeypatch,
) -> None:
    installed: list[TracerProvider] = []
    monkeypatch.setattr(
        otel_trace, "set_tracer_provider", lambda provider: installed.append(provider)
    )
    assert configure_tracing_from_env(env={}, install_global=True) is None
    assert installed == []


def test_configure_from_env_enabled_installs_global_provider(monkeypatch) -> None:
    installed: list[TracerProvider] = []
    monkeypatch.setattr(
        otel_trace, "set_tracer_provider", lambda provider: installed.append(provider)
    )
    setup = configure_tracing_from_env(
        env={ENV_OTLP_ENDPOINT: "https://collector.example/v1/traces"}, install_global=True
    )
    assert setup is not None
    assert installed == [setup.provider]
    assert setup.config.enabled is True


def test_pipeline_redacts_sensitive_attributes_before_delegate() -> None:
    config = OtelExportConfig.from_env({ENV_OTLP_ENDPOINT: "https://collector.example/v1/traces"})
    delegate = ScriptedDelegate()
    setup = build_export_pipeline(config, delegate=delegate, batched=False)
    tracer = setup.provider.get_tracer("oaa.test")

    with tracer.start_as_current_span("oaa.test.span") as span:
        span.set_attribute("oaa.secret_demo", AWS_KEY_FIXTURE)
        span.set_attribute("oaa.metadata_only", "synthetic_public")

    assert len(delegate.span_calls) == 1
    exported = delegate.span_calls[0][0]
    assert dict(exported.attributes)["oaa.secret_demo"] == AWS_KEY_TOKEN
    assert dict(exported.attributes)["oaa.metadata_only"] == "synthetic_public"
    assert AWS_KEY_FIXTURE not in str(delegate.span_calls)


def test_pipeline_loss_is_visible_then_marker_after_recovery() -> None:
    config = OtelExportConfig.from_env(
        {
            ENV_OTLP_ENDPOINT: "https://collector.example/v1/traces",
            ENV_OTLP_MAX_ATTEMPTS: "2",
        }
    )
    delegate = ScriptedDelegate(
        [ConnectionRefusedError()] * 2 + [SpanExportResult.SUCCESS] * 2 + [SpanExportResult.SUCCESS]
    )
    setup = build_export_pipeline(config, delegate=delegate, batched=False)
    tracer = setup.provider.get_tracer("oaa.test")

    with tracer.start_as_current_span("oaa.during_outage"):
        pass
    assert setup.exporter.metrics["spans_dropped"] == 1
    assert len(delegate.span_calls) == 2

    with tracer.start_as_current_span("oaa.after_recovery"):
        pass
    assert setup.exporter.metrics["marker_spans_sent"] == 1
    assert delegate.span_calls[3][0].name == MARKER_SPAN_NAME


# -- downstream egress helpers -------------------------------------------------


def test_traceparent_from_span_context_round_trips() -> None:
    provider = TracerProvider()
    tracer = provider.get_tracer("oaa.test")
    with tracer.start_as_current_span("oaa.egress") as span:
        header = traceparent_from_span_context(span.get_span_context())
        parsed = parse_traceparent(header)
        assert parsed is not None
        assert parsed.trace_id == format(span.get_span_context().trace_id, "032x")
        assert parsed.parent_span_id == format(span.get_span_context().span_id, "016x")


def test_inject_w3c_headers_sets_traceparent_and_tracestate() -> None:
    provider = TracerProvider()
    tracer = provider.get_tracer("oaa.test")
    with tracer.start_as_current_span("oaa.egress") as span:
        ctx = span.get_span_context()
        carrying = NonRecordingSpan(
            SpanContext(
                trace_id=ctx.trace_id,
                span_id=ctx.span_id,
                is_remote=False,
                trace_flags=ctx.trace_flags,
                trace_state=otel_trace.TraceState([("congo", "t61rcWkgMzE")]),
            )
        )
        headers: dict[str, str] = {}
        inject_w3c_headers(headers, carrying)
        assert parse_traceparent(headers["traceparent"]) is not None
        assert headers["tracestate"] == "congo=t61rcWkgMzE"


def test_inject_w3c_headers_omits_empty_tracestate() -> None:
    provider = TracerProvider()
    tracer = provider.get_tracer("oaa.test")
    with tracer.start_as_current_span("oaa.egress") as span:
        headers: dict[str, str] = {}
        inject_w3c_headers(headers, span)
        assert "traceparent" in headers
        assert "tracestate" not in headers
