#!/usr/bin/env python3
"""OPS-01 load smoke: bounded steady-state producer against the LOCAL reference stack.

Based on examples/reference-agent/reference_agent.py (same oaa.* attribute namespace,
AGENT root -> LLM stub -> RETRIEVER -> TOOL, direct OTLP HTTP to Langfuse).

Profile (defaults, overridable by CLI):
  10 runs/sec x 20 spans x 120s measured window (1,200 traces / 24,000 spans)
  preceded by a 30s no-export baseline (same span shapes, spans discarded).

Overhead metric: per-run producer wall-clock (time to emit 20 spans), p95 of the
measured window vs p95 of the no-export baseline. This is a smoke, not a benchmark.
Output: ops/scratch/load-report.json.
"""

from __future__ import annotations

import argparse
import base64
import json
import pathlib
import statistics
import sys
import time

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

REPO = pathlib.Path(__file__).resolve().parents[2]


def load_env(env_path: pathlib.Path) -> dict:
    env = {}
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, _, v = line.partition("=")
            env[k] = v.split("#")[0].strip()
    return env


def build_provider(export: bool, url: str, pk: str, sk: str):
    provider = TracerProvider(
        resource=Resource.create({"service.name": "oaa-loadgen", "service.version": "ops01-smoke"})
    )
    if export:
        exporter = OTLPSpanExporter(
            endpoint=f"{url}/api/public/otel/v1/traces",
            headers={
                "Authorization": "Basic "
                + base64.b64encode(f"{pk}:{sk}".encode()).decode()
            },
            timeout=20,
        )
        provider.add_span_processor(BatchSpanProcessor(exporter, max_export_batch_size=512))
    else:
        # no-export baseline: batch processor with an InMemory sink (same queueing
        # shape, no HTTP egress; bounded window keeps memory trivial)
        provider.add_span_processor(BatchSpanProcessor(InMemorySpanExporter(), max_export_batch_size=512))
    return provider


class _VoidProcessor:  # unused — kept for API shape documentation
    def __getattr__(self, name):
        raise RuntimeError("void processor is not used; baseline uses InMemorySpanExporter")


def emit_run(tracer, seq: int, run_id: str) -> None:
    root = tracer.start_as_current_span(
        "oaa.agent.main",
        attributes={
            "openinference.span.kind": "AGENT",
            "oaa.run_id": run_id,
            "oaa.release_version": "v0.23.5+63edacd",
            "oaa.trace_label": f"oaa-load-{run_id}",
            "oaa.content_class": "synthetic_public",
            "langfuse.session.id": f"sess-{run_id}",
        },
    )
    with root:
        for i in range(19):  # 20 spans total incl root
            with tracer.start_as_current_span(
                f"oaa.step.{i % 4}",
                attributes={
                    "openinference.span.kind": ["LLM", "RETRIEVER", "TOOL", "AGENT"][i % 4],
                    "oaa.run_id": run_id,
                    "oaa.step_index": str(i),
                    "oaa.content_class": "synthetic_public",
                },
            ):
                pass


def run_window(provider, tracer, rate: float, spans_per_run, seconds: float, export: bool):
    """Emit `rate` runs/sec for `seconds`; return list of per-run wall-clock durations (s)."""
    durations = []
    interval = 1.0 / rate
    deadline = time.time() + seconds
    seq = 0
    next_at = time.time()
    while time.time() < deadline:
        run_id = f"load-{'exp' if export else 'base'}-{int(time.time() * 1000)}-{seq}"
        t0 = time.perf_counter()
        emit_run(tracer, seq, run_id)
        durations.append(time.perf_counter() - t0)
        seq += 1
        next_at += interval
        delay = next_at - time.time()
        if delay > 0:
            time.sleep(delay)
        else:
            next_at = max(next_at, time.time())
    return durations, seq


def p95(vals):
    s = sorted(vals)
    return s[max(0, int(len(s) * 0.95) - 1)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", default="/home/craigamcw/oaa-reference-stack/.env")
    ap.add_argument("--url", default=None)
    ap.add_argument("--out", default=str(REPO / "ops/scratch/load-report.json"))
    ap.add_argument("--rate", type=float, default=10.0)
    ap.add_argument("--duration", type=float, default=120.0)
    ap.add_argument("--baseline-duration", type=float, default=30.0)
    ap.add_argument("--max-spans-per-run", type=int, default=20)
    args = ap.parse_args()

    env = load_env(pathlib.Path(args.env))
    url = args.url or env.get("OAA_LF_URL", "http://127.0.0.1:3301")
    pk = env["OAA_LF_PUBLIC_KEY"] or env["LANGFUSE_INIT_PROJECT_PUBLIC_KEY"]
    sk = env["OAA_LF_SECRET_KEY"] or env["LANGFUSE_INIT_PROJECT_SECRET_KEY"]


    # baseline (no export)
    provider = build_provider(False, url, pk, sk)
    tracer = provider.get_tracer("oaa.loadgen", "1.0.0")
    base_d, base_runs = run_window(provider, tracer, args.rate, 20, args.baseline_duration, False)
    provider.shutdown()

    # measured (export)
    provider = build_provider(True, url, pk, sk)
    tracer = provider.get_tracer("oaa.loadgen", "1.0.0")
    exp_d, exp_runs = run_window(provider, tracer, args.rate, 20, args.duration, True)
    provider.force_flush()
    provider.shutdown()

    report = {
        "profile": {
            "rate_runs_per_sec": args.rate,
            "spans_per_run": 20,
            "duration_sec": args.duration,
            "baseline_duration_sec": args.baseline_duration,
            "target_stack": url,
        },
        "runs": {
            "measured": exp_runs,
            "baseline": base_runs,
        },
        "spans": {
            "measured_estimated": exp_runs * 20,
            "baseline_estimated": base_runs * 20,
        },
        "wall_clock_ms_per_run": {
            "measured_p50": round(statistics.median(exp_d) * 1000, 3),
            "measured_p95": round(p95(exp_d) * 1000, 3),
            "measured_max": round(max(exp_d) * 1000, 3),
            "baseline_p50": round(statistics.median(base_d) * 1000, 3),
            "baseline_p95": round(p95(base_d) * 1000, 3),
            "baseline_max": round(max(base_d) * 1000, 3),
        },
        "overhead": {
            "p95_overhead_ms_vs_no_export_baseline": round((p95(exp_d) - p95(base_d)) * 1000, 3),
            "p95_overhead_ratio": round(p95(exp_d) / max(p95(base_d), 1e-9), 3),
        },
        "note": "smoke, not a benchmark; single host, batch export max_export_batch_size=512",
    }
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
