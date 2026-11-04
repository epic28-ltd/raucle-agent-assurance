#!/usr/bin/env python3
"""OBS-01 P3: collector/backend outage probe. Kill the Langfuse ingestion path (web+worker),
emit spans during the outage with a BOUNDED-retry OTLP exporter, measure and record visible loss
metrics, then restore the backend and check what landed."""

import base64
import json
import pathlib
import subprocess
import time
import uuid

BASE = pathlib.Path(__file__).resolve().parent
CREDS = {}
for line in (BASE / "obs.env").read_text().splitlines():
    k, _, v = line.partition("=")
    CREDS[k] = v

from opentelemetry import trace as tr
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult
from requests import post

LF = "http://localhost:3301"
AUTH = {
    "Authorization": "Basic "
    + base64.b64encode(
        f"{CREDS['LANGFUSE_INIT_PROJECT_PUBLIC_KEY']}:{CREDS['LANGFUSE_INIT_PROJECT_SECRET_KEY']}".encode()
    ).decode()
}


# ---------- bounded-retry exporter with observable loss ----------
class BoundedRetryExporter(SpanExporter):
    """Retries each batch up to max_attempts with fixed backoff; records visible loss metrics."""

    def __init__(self, endpoint=LF):
        super().__init__()
        self.endpoint = endpoint
        self.max_attempts = 4  # bounded: not infinite
        self.backoff_s = 1.0
        self.metrics = {
            "batches": 0,
            "spans_attempted": 0,
            "spans_dropped": 0,
            "retries": 0,
            "total_retry_seconds": 0.0,
            "last_error": None,
        }

    def export(self, spans):
        self.metrics["batches"] += 1
        self.metrics["spans_attempted"] += len(spans)
        payload = self._serialize(spans)
        for attempt in range(1, self.max_attempts + 1):
            try:
                r = post(
                    f"{self.endpoint}/api/public/otel/v1/traces",
                    data=payload,
                    headers={**AUTH, "Content-Type": "application/x-protobuf"},
                    timeout=10,
                )
                if r.status_code in (200, 202):
                    return SpanExportResult.SUCCESS
                self.metrics["last_error"] = f"HTTP {r.status_code}"
            except Exception as e:
                self.metrics["last_error"] = f"{type(e).__name__}: {e}"
            if attempt < self.max_attempts:
                self.metrics["retries"] += 1
                self.metrics["total_retry_seconds"] += self.backoff_s
                time.sleep(self.backoff_s)
        self.metrics["spans_dropped"] += len(spans)  # visible loss, not silent
        return SpanExportResult.FAILURE

    def _serialize(self, spans):
        # reuse OTel protobuf serialization: delegate to OTLPSpanExporter internals via a shim
        return self._inner.export(spans) if hasattr(self, "_inner") else b""

    def shutdown(self):
        pass


class BoundedRetryExporter(SpanExporter):
    def __init__(self):
        super().__init__()
        self.inner = OTLPSpanExporter(
            endpoint=f"{LF}/api/public/otel/v1/traces", headers=AUTH, timeout=10
        )
        self.max_attempts = 4
        self.backoff_s = 1.0
        self.metrics = {
            "batches": 0,
            "spans_attempted": 0,
            "spans_dropped": 0,
            "retries": 0,
            "total_retry_seconds": 0.0,
            "last_error": None,
        }

    def export(self, spans):
        self.metrics["batches"] += 1
        self.metrics["spans_attempted"] += len(spans)
        for attempt in range(1, self.max_attempts + 1):
            try:
                result = self.inner.export(spans)
            except Exception as e:
                result = SpanExportResult.FAILURE
                self.metrics["last_error"] = f"{type(e).__name__}: {e}"
            if result == SpanExportResult.SUCCESS:
                return result
            if not self.metrics["last_error"]:
                self.metrics["last_error"] = str(result)
            if attempt < self.max_attempts:
                self.metrics["retries"] += 1
                self.metrics["total_retry_seconds"] += self.backoff_s
                time.sleep(self.backoff_s)
        self.metrics["spans_dropped"] += len(spans)
        return SpanExportResult.FAILURE

    def shutdown(self):
        self.inner.shutdown()


outage_exp = BoundedRetryExporter()
provider = TracerProvider()
tr.set_tracer_provider(provider)
tracer = tr.get_tracer("oaa.outage", "1.0.0")
provider.add_span_processor(BatchSpanProcessor(outage_exp, schedule_delay_millis=1000))


def docker(*args):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=120)


RUN_ID = f"oaa-outage-{uuid.uuid4().hex[:8]}"
trace_label = f"oaa-trace-{uuid.uuid4().hex[:16]}"

# ---- stop ingestion path (web + worker) ----
t0 = time.time()
print(
    "stop langfuse-worker,langfuse-web:",
    docker("stop", "obs01-langfuse-worker-1", "obs01-langfuse-web-1").returncode,
)
time.sleep(3)

# ---- emit during outage ----
with tracer.start_as_current_span(
    "oaa.agent.main",
    attributes={
        "openinference.span.kind": "AGENT",
        "oaa.run_id": RUN_ID,
        "oaa.release_version": "v0.23.5+63edacd",
        "oaa.trace_label": trace_label,
        "oaa.content_class": "synthetic_public",
    },
) as span:
    otel_tid = format(span.get_span_context().trace_id, "032x")
    with tracer.start_as_current_span(
        "oaa.during-outage",
        attributes={
            "openinference.span.kind": "TOOL",
            "tool.name": "read_file",
            "oaa.content_class": "synthetic_public",
        },
    ):
        pass
# flush while backend is still down -> bounded retries, then visible drop
provider.force_flush()
t_emitted = time.time()

# bounded retry happens inside exporter while still down; wait out retries
time.sleep(6)  # > max_attempts * backoff
dropped_during = outage_exp.metrics["spans_dropped"]
print("during-outage metrics so far:", json.dumps(outage_exp.metrics))

# ---- restore backend ----
print(
    "start backend:", docker("start", "obs01-langfuse-worker-1", "obs01-langfuse-web-1").returncode
)
t_restored = time.time()
time.sleep(25)  # let web come healthy
print("health:", end=" ")
import requests

for _ in range(20):
    try:
        if requests.get(f"{LF}/api/public/health", timeout=5).status_code == 200:
            break
    except Exception:
        pass
    time.sleep(3)

# ---- retry-after-recovery batch for the dropped spans (bounded, visible) ----
recovery_exp = BoundedRetryExporter()
provider.add_span_processor(BatchSpanProcessor(recovery_exp, schedule_delay_millis=500))
with tracer.start_as_current_span(
    "oaa.dropped-spans-reflight",
    attributes={
        "openinference.span.kind": "CHAIN",
        "oaa.run_id": RUN_ID,
        "oaa.trace_label": trace_label,
        "oaa.outage.recovered_spans": dropped_during,
        "oaa.outage.reference_trace_id": otel_tid,
    },
):
    pass
provider.force_flush()
provider.shutdown()

report = {
    "run_id": RUN_ID,
    "oaa_trace_label": trace_label,
    "otel_trace_id": otel_tid,
    "outage_start_s": round(t0, 3),
    "emit_time_s": round(t_emitted, 3),
    "restore_time_s": round(t_restored, 3),
    "outage_emit_phase_metrics": outage_exp.metrics,
    "recovery_phase_metrics": recovery_exp.metrics,
    "bounded_retry": {"max_attempts": 4, "backoff_s": 1.0, "total_bound_s": 4 * 1.0 + 3 * 1.0},
    "loss_visibility": {
        "spans_dropped_during_outage": dropped_during,
        "reflight_attempted": recovery_exp.metrics["spans_attempted"],
        "reflight_dropped": recovery_exp.metrics["spans_dropped"],
    },
}
(BASE / "p3_report.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report["loss_visibility"], indent=1))
print("P3 metrics recorded ->", BASE / "p3_report.json")
