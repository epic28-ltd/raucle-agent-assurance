"""COR-01 optional Langfuse smoke: attach a receipt_hash score to a trace id.

Mirrors the OBS-01 P5 pattern (~/Projects/oaa-spike-4nov/obs01/p2_p5_correlation.py):
post a score whose comment carries ``receipt_hash=...`` for the correlated
trace id, then read it back. SYNTHETIC data only — the receipt hash here is a
fake digest, never a canonical evidence artefact. Runs only when the local
Langfuse stack (obs01 compose, web on 127.0.0.1:3301) is reachable; otherwise
raises SkipTest so callers/CI skip cleanly.

Usage:  python services/correlation/integrations/langfuse_smoke.py
Env:    OAA_LANGFUSE_URL (default http://127.0.0.1:3301)
        OAA_LANGFUSE_ENV (default ~/Projects/oaa-spike-4nov/obs01/obs.env —
        holds LANGFUSE_INIT_PROJECT_PUBLIC_KEY / _SECRET_KEY; never committed)
"""
# SPDX-License-Identifier: FSL-1.1-ALv2

from __future__ import annotations

import datetime as dt
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

from oaa_correlation import (
    CorrelationConfig,
    ReceiptRecord,
    TraceRecord,
    reconcile,
)

DEFAULT_URL = "http://127.0.0.1:3301"
DEFAULT_ENV = pathlib.Path("~/Projects/oaa-spike-4nov/obs01/obs.env").expanduser()

TRACE_ID = "cor01-smoke-trace-0001"
SYNTHETIC_RECEIPT_HASH = "sha256:" + "0" * 63 + "1"  # fake digest, synthetic only


class SkipTest(Exception):
    pass


def _health(url: str, timeout: float = 5.0) -> bool:
    try:
        with urllib.request.urlopen(f"{url}/api/public/health", timeout=timeout) as resp:
            return resp.status == 200
    except OSError:
        return False


def _keys(env_path: pathlib.Path) -> tuple[str, str]:
    if not env_path.exists():
        raise SkipTest(f"Langfuse env file not found: {env_path}")
    vals = {}
    for line in env_path.read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            vals[k] = v
    pub = vals.get("LANGFUSE_INIT_PROJECT_PUBLIC_KEY")
    sec = vals.get("LANGFUSE_INIT_PROJECT_SECRET_KEY")
    if not (pub and sec):
        raise SkipTest("project keys missing from env file")
    return pub, sec


def _exists_trace(base: str, trace_id: str, headers: dict[str, str]) -> bool:
    try:
        with urllib.request.urlopen(
            urllib.request.Request(f"{base}/api/public/traces/{trace_id}", headers=headers),
            timeout=20,
        ) as resp:
            return resp.status == 200
    except urllib.error.HTTPError:
        return False


def run_smoke(url: str | None = None) -> dict:
    """Correlate synthetically, attach a receipt_hash score, read back."""
    base = url or os.environ.get("OAA_LANGFUSE_URL", DEFAULT_URL)
    if not _health(base):
        raise SkipTest(f"Langfuse stack not reachable at {base}")

    # Correlate offline first — the engine must emit `matched` before anything
    # is attached to the backend.
    now = dt.datetime.now(dt.UTC)
    result = reconcile(
        [
            ReceiptRecord(
                receipt_hash=SYNTHETIC_RECEIPT_HASH,
                trace_id=TRACE_ID,
                decision="allow",
                event_time=now,
                provenance="cor01-smoke-synthetic",
                synthetic=True,
            )
        ],
        [TraceRecord(trace_id=TRACE_ID, tool_invocation="cor01-smoke-tool", observed_at=now)],
        CorrelationConfig(),
        at=now + dt.timedelta(seconds=60),
    )
    records = result.by_state("matched")
    if len(records) != 1:
        raise RuntimeError(f"smoke correlation expected 1 matched record, got {records}")

    pub, sec = _keys(DEFAULT_ENV)
    import base64

    basic = base64.b64encode(f"{pub}:{sec}".encode()).decode()
    headers = {"Authorization": f"Basic {basic}", "Content-Type": "application/json"}
    score_id = "cor01-smoke-score-0001"
    # The backend rejects scores for unknown trace ids — create the synthetic
    # trace first (synthetic name; no real content attributes — invariant 8).
    trace_body = {
        "id": TRACE_ID,
        "name": "cor01-smoke",
        "timestamp": now.isoformat(),
    }
    req = urllib.request.Request(
        f"{base}/api/public/traces",
        data=json.dumps(trace_body).encode(),
        headers=headers,
    )
    try:
        urllib.request.urlopen(req, timeout=20).read()
    except urllib.error.HTTPError:
        if not _exists_trace(base, TRACE_ID, headers):
            raise
    body = {
        "id": score_id,
        "traceId": TRACE_ID,
        "name": "cor01.correlation",
        "value": 1.0,
        "dataType": "NUMERIC",
        "comment": f"cor01;receipt_hash={SYNTHETIC_RECEIPT_HASH};synthetic=true",
    }
    req = urllib.request.Request(
        f"{base}/api/public/scores", data=json.dumps(body).encode(), headers=headers
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        posted = json.loads(resp.read())
    with urllib.request.urlopen(
        urllib.request.Request(f"{base}/api/public/scores/{score_id}", headers=headers),
        timeout=20,
    ) as resp:
        readback = json.loads(resp.read())

    ok = readback.get("traceId") == TRACE_ID and readback.get("comment") == body["comment"]
    return {
        "ok": bool(ok),
        "post_status": posted,
        "readback": readback,
        "correlation_state": records[0].state,
    }


if __name__ == "__main__":
    try:
        out = run_smoke()
    except SkipTest as skip:
        print(f"SKIP: {skip}")
        sys.exit(0)
    print(json.dumps(out, indent=2, default=str))
    sys.exit(0 if out["ok"] else 1)
