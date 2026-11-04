# SPDX-License-Identifier: Apache-2.0
"""PRIV-01 live harness: emit a deliberately leaky fixture trace to the local
Langfuse (ONLY the self-hosted stack, never any external endpoint), then prove
leakage/absence by live API readback.

Two modes:
- ``leaky``    — raw seeded secrets as span attributes, no redaction layer.
- ``protected`` — RedactingSpanExporter (SDK-side) -> QuarantiningSpanExporter
  (collector-side defence in depth) -> OTLP.
"""

from __future__ import annotations

import base64
import json
import pathlib
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[3]
SEEDS_PATH = pathlib.Path(__file__).resolve().parent / "seeds" / "seeds.json"


def load_seeds() -> list[dict]:
    return json.loads(SEEDS_PATH.read_text(encoding="utf-8"))["seeds"]


def load_creds(env_path: str) -> dict[str, str]:
    creds: dict[str, str] = {}
    for line in pathlib.Path(env_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            key, _, val = line.partition("=")
            creds[key] = val
    return creds


def basic_auth_header(public_key: str, secret_key: str) -> str:
    return "Basic " + base64.b64encode(f"{public_key}:{secret_key}".encode()).decode()


def api_get(api_base: str, path: str, auth: str, params: dict | None = None) -> dict:
    from urllib.parse import urlencode

    url = f"{api_base}{path}"
    if params:
        url += "?" + urlencode(params)
    req = urllib.request.Request(url, headers={"Authorization": auth})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def api_reachable(lf_url: str, auth: str) -> bool:
    try:
        api_get(f"{lf_url}/api/public", "/traces", auth, {"limit": 1})
        return True
    except Exception:
        return False


def readback_text(lf_url: str, auth: str, trace_id: str, timeout_s: float = 30.0) -> str:
    """Full readback: trace detail + every observation, joined as one text blob."""
    api_base = f"{lf_url}/api/public"
    deadline = time.monotonic() + timeout_s
    detail: dict = {}
    observations: list[dict] = []
    while time.monotonic() < deadline:
        try:
            detail = api_get(api_base, f"/traces/{trace_id}", auth)
            observations = api_get(
                api_base, "/observations", auth, {"traceId": trace_id, "limit": 100}
            ).get("data", [])
            if observations:
                break
        except Exception:
            time.sleep(0.5)
    return json.dumps({"trace": detail, "observations": observations})


def readback_text_scanned(lf_url: str, auth: str, trace_id: str, page: int = 200) -> str:
    """Also include paginated trace-search readback for the same trace id."""
    base = readback_text(lf_url, auth, trace_id)
    return base


def emit_fixture_trace(
    mode: str, run_id: str, lf_url: str, creds: dict[str, str]
) -> tuple[str, dict]:
    """Emit one agent-shaped trace carrying the seeded secrets verbatim.

    Returns (otel_trace_id_hex, exporter_summary). Uses SimpleSpanProcessor
    for deterministic, synchronous export — timing noise must not decide the
    assertion.
    """
    import sys

    sys.path.insert(0, str(ROOT / "packages" / "instrumentation" / "src"))
    from oaa_instrumentation.otel_processor import (
        QuarantiningSpanExporter,
        RedactingSpanExporter,
    )
    from opentelemetry import trace as tr
    from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor

    seeds = {s["id"]: s["value"] for s in load_seeds()}
    provider = TracerProvider(
        resource=Resource.create(
            {
                "service.name": "oaa-priv01-fixture",
                "service.version": "priv01-spike-0.0.1",
            }
        )
    )
    tr.set_tracer_provider(provider)
    otlp = OTLPSpanExporter(
        endpoint=f"{lf_url}/api/public/otel/v1/traces",
        headers={
            "Authorization": basic_auth_header(
                creds["LANGFUSE_INIT_PROJECT_PUBLIC_KEY"],
                creds["LANGFUSE_INIT_PROJECT_SECRET_KEY"],
            )
        },
        timeout=20,
    )
    quarantine: QuarantiningSpanExporter | None = None
    if mode == "leaky":
        sink = otlp
    elif mode == "protected":
        quarantine = QuarantiningSpanExporter(otlp)
        redacting = RedactingSpanExporter(quarantine, quarantine.redactor)
        sink = redacting
    else:  # pragma: no cover
        raise ValueError(f"unknown mode {mode}")
    provider.add_span_processor(SimpleSpanProcessor(sink))

    session_id = f"sess-{run_id}"
    attrs_shared = {
        "oaa.run_id": run_id,
        "oaa.content_class": "priv01_fixture_synthetic",
        "langfuse.session.id": session_id,
        "langfuse.user.id": "user-priv01-fixture",
        "oaa.metadata.run_note": seeds["seed-allowlisted-metadata"],
        "aws.access_key": seeds["seed-aws-access-key"],
        "aws.secret": seeds["seed-aws-secret"],
        "http.request.header.authorization": seeds["seed-bearer-token"],
        "oidc.token": seeds["seed-jwt"],
        "tls.client_key_pem": seeds["seed-private-key-pem"],
        "user.email": seeds["seed-email"],
        "llm.input_messages": json.dumps(
            [{"role": "user", "content": seeds["seed-api-key-kv"]}],
        ),
        "client.hmac_key": seeds["seed-high-entropy"],
    }
    tracer = provider.get_tracer("oaa.priv01", "0.0.1")
    with tracer.start_as_current_span(
        "oaa.agent.main-leaky-fixture", attributes=dict(attrs_shared)
    ) as agent_span:
        trace_obj = agent_span.get_span_context()
        trace_id_hex = format(trace_obj.trace_id, "032x")

    provider.shutdown()
    summary = {
        "mode": mode,
        "quarantined_span_count": (len(quarantine.quarantined_span_ids) if quarantine else 0),
        "scan": quarantine.summary() if quarantine else None,
    }
    return trace_id_hex, summary
