# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Open Agent Assurance contributors
"""PRIV-01 P0 acceptance: seeded-secret leak proof against a live Langfuse.

Runs WITHOUT network beyond the self-hosted stack (default
http://127.0.0.1:3301). Requires ``OAA_PRIV01_LF_ENV_FILE`` to point at the
stack's env file (project key / secret key / endpoint) — otherwise the test
SKIPS, so bare CI never depends on the stack.

(a) leaky mode: the seeded secrets persist in the backend — proves the
    harness and live readback catch leakage.
(b) protected mode: SDK redaction + collector quarantine installed — the
    seeded secrets are absent from the live API readback and the collector
    scan reports zero violations.
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent / "fixtures"

pytest.importorskip("opentelemetry.sdk.trace", reason="opentelemetry-sdk not installed")
sys.path.insert(0, str(FIXTURES))

import leak_harness as H

DEFAULT_LF_URL = "http://127.0.0.1:3301"


@pytest.fixture(scope="module")
def lf() -> tuple[str, str]:
    env_file = os.environ.get("OAA_PRIV01_LF_ENV_FILE", "")
    if not env_file or not Path(env_file).exists():
        pytest.skip("OAA_PRIV01_LF_ENV_FILE not set: live proof requires the local stack env file")
    creds = H.load_creds(env_file)
    lf_url = os.environ.get("OAA_LF_URL", DEFAULT_LF_URL)
    auth = H.basic_auth_header(
        creds["LANGFUSE_INIT_PROJECT_PUBLIC_KEY"],
        creds["LANGFUSE_INIT_PROJECT_SECRET_KEY"],
    )
    if not H.api_reachable(lf_url, auth):
        pytest.skip(f"local Langfuse stack not reachable at {lf_url}")
    return lf_url, auth


def sensitive_seeds() -> list[dict]:
    return [s for s in H.load_seeds() if s["class"] != "allowlisted"]


def allowlisted_seed() -> dict:
    return next(s for s in H.load_seeds() if s["class"] == "allowlisted")


def test_priv01_a_without_redaction_seeds_persist(lf) -> None:
    """Counterfactual (a): with NO redaction installed, every seeded secret
    persists in the trace store and the live readback finds it."""
    lf_url, auth = lf
    run_id = f"priv01-leaky-{uuid.uuid4().hex[:10]}"
    trace_id, summary = H.emit_fixture_trace("leaky", run_id, lf_url, _creds_for())
    text = H.readback_text(lf_url, auth, trace_id).replace("\\n", "\n")
    assert summary["mode"] == "leaky"
    for seed in sensitive_seeds():
        assert seed["value"] in text, (
            f"counterfactual failed: {seed['id']} NOT persisted in readback for {trace_id}"
        )
    # the metadata namespace also travels when the value carries no secret
    assert allowlisted_seed()["value"] in text


def test_priv01_b_with_redaction_seeds_absent(lf) -> None:
    """Layered (b): SDK redaction + collector quarantine; sensitive seeds are
    ABSENT from the live readback, and the collector scan is clean."""
    lf_url, auth = lf
    run_id = f"priv01-prot-{uuid.uuid4().hex[:10]}"
    trace_id, summary = H.emit_fixture_trace("protected", run_id, lf_url, _creds_for())
    text = H.readback_text(lf_url, auth, trace_id).replace("\\n", "\n")
    for seed in sensitive_seeds():
        assert seed["value"] not in text, (
            f"LEAK: {seed['id']} persisted despite redaction for {trace_id}"
        )
    # a non-secret metadata note still travels (values, not keys, are governed)
    assert allowlisted_seed()["value"] in text
    # redaction tokens ARE present, with class tags
    assert text.count("[REDACTED:") >= 1
    # collector-side scan over the (post-SDK-scrub) export batch: zero
    scan = summary["scan"]
    assert scan is not None
    assert scan["clean"] is True
    assert scan["violation_count"] == 0
    assert summary["quarantined_span_count"] == 0
    # and the SDK layer counted what it scrubbed
    write_run_artifact(trace_id, run_id, text, summary)


def _creds_for() -> dict[str, str]:
    env_file = os.environ.get("OAA_PRIV01_LF_ENV_FILE", "")
    return H.load_creds(env_file)


def write_run_artifact(trace_id: str, run_id: str, readback_text: str, summary: dict) -> None:
    """Persist a redaction-safe proof artifact (seeds values never included)."""
    out = FIXTURES / "run-artifacts"
    out.mkdir(parents=True, exist_ok=True)
    payload = {
        "trace_id": trace_id,
        "run_id": run_id,
        "summary": summary,
        "redacted_tokens_in_readback": readback_text.count("[REDACTED:"),
        "seeds_scanned": [s["id"] for s in sensitive_seeds()],
    }
    (out / f"priv01-{trace_id[:16]}.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n"
    )
