# SPDX-License-Identifier: Apache-2.0
"""RED-INTEGRATION — end-to-end tests for the red findings intake.

Covers the ingestion contract (POST /api/findings/ingest):

- idempotency by finding_id (re-posting a run is a no-op);
- evidence integrity re-verification for local path references (a sha256
  mismatch is rejected 422; a matching path is accepted);
- the red ingest endpoint accepts the corpora shape (JSONL text, JSON
  array, {"findings": [...]}) and rejects invalid findings (unknown
  severity, non-UUID5 id, missing fields);
- counting integration: /api/counts total = assurance findings + red
  ingested, the red section agrees, and the lens partition still closes;
- the board renders ingested red rows tagged source 'red-mvp' with
  per-rule guidance (known rule and generic fallback); /api/findings/red
  returns the same slice board-shaped;
- console Red page copy: the honest product line replaced the teaser and
  the ingested-findings card fetches the red slice.

Runs against a throwaway copy of the demo fixture dir so the repo data
stays clean; no network access anywhere (the console copy test parses the
static file only).
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import sys
import uuid

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
UI = REPO_ROOT / "services" / "investigation-ui"
CONSOLE_HTML = REPO_ROOT / "services" / "console" / "static" / "index.html"

for _p in (str(UI / "src"),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi.testclient import TestClient  # noqa: E402
from oaa_investigation_ui.app import create_app  # noqa: E402
from oaa_investigation_ui.red_intake import (  # noqa: E402
    RED_SOURCE,
    red_guidance,
)

DATA_DIR = UI / "demo_data"


def _example_finding(
    *, severity: str = "medium", rule: str = "RED-003", finding_id: str | None = None
) -> dict:
    return {
        "finding_id": finding_id or str(uuid.uuid5(uuid.NAMESPACE_URL, "red|test|1")),
        "rule": rule,
        "rule_label": "tamper probe",
        "severity": severity,
        "confidence": "high",
        "evidence_ref": {"kind": "audit_row", "value": "a" * 64, "sha256": "b" * 64},
        "explanation": "probe observed a tamper attempt being contained",
        "suggested_action": "confirm containment in the gate log",
        "suite": "tamper",
    }


@pytest.fixture
def client(tmp_path: pathlib.Path) -> TestClient:
    shutil.copytree(DATA_DIR, tmp_path / "demo")
    # red_findings.json is runtime state: a live dev-server ingest leaves rows
    # in demo_data, and fixture copies must start from a clean slate so counts
    # assert on the test's own ingest rather than leaked operator state.
    leaked = tmp_path / "demo" / "red_findings.json"
    if leaked.exists():
        leaked.unlink()
    return TestClient(create_app(tmp_path / "demo"))


# --------------------------------------------------------------- intake
def test_ingest_and_board_render(client: TestClient):
    r = client.post("/api/findings/ingest", json=[_example_finding(severity="high")])
    assert r.status_code == 200
    assert r.json() == {
        "ingested": True,
        "source": RED_SOURCE,
        "total": 1,
        "accepted": 1,
        "replaced": 0,
        "new": 1,
    }

    red = client.get("/api/findings/red").json()
    assert red["source"] == RED_SOURCE
    assert red["by_severity"]["high"] == 1

    board = client.get("/api/findings/board").json()
    rows = [f for f in board["findings"] if f["source"] == RED_SOURCE]
    assert len(rows) == 1
    row = rows[0]
    assert row["rule_id"] == "RED-003"
    assert row["lens"] == "needs"  # high → needs (board short lens; counting translates)
    assert row["guidance"] == red_guidance("RED-003")
    assert row["state"] == "new"
    assert row["id"] == "red-" + _example_finding()["finding_id"]


def test_generic_guidance_fallback(client: TestClient):
    f = _example_finding(rule="RED-999")
    client.post("/api/findings/ingest", json=[f])
    row = next(
        r for r in client.get("/api/findings/board").json()["findings"] if r["source"] == RED_SOURCE
    )
    assert row["guidance"] == red_guidance("RED-999")
    assert "Red probe finding" in row["guidance"]


def test_ingest_idempotent_by_finding_id(client: TestClient):
    f = _example_finding()
    assert client.post("/api/findings/ingest", json=[f]).json()["total"] == 1
    again = client.post("/api/findings/ingest", json=[f, f])
    assert again.status_code == 200
    body = again.json()
    assert body["total"] == 1  # same id, still one stored finding
    assert body["replaced"] == 2
    assert body["new"] == 0
    board = client.get("/api/findings/board").json()
    assert sum(1 for r in board["findings"] if r["source"] == RED_SOURCE) == 1


def test_jsonl_body_parses_like_the_corpora(client: TestClient, tmp_path: pathlib.Path):
    # local-path reference: file exists and its sha256 matches → accepted
    evidence = tmp_path / "evidence.bin"
    evidence.write_bytes(b"tamper probe payload")
    digest = hashlib.sha256(evidence.read_bytes()).hexdigest()
    f = {
        **_example_finding(),
        "evidence_ref": {"kind": "fixture_store", "value": str(evidence), "sha256": digest},
    }
    r = client.post(
        "/api/findings/ingest",
        content=json.dumps(f) + "\n",
        headers={"content-type": "text/plain"},
    )
    assert r.status_code == 200
    assert r.json()["total"] == 1


def test_integrity_mismatch_rejected(client: TestClient, tmp_path: pathlib.Path):
    evidence = tmp_path / "tampered.bin"
    evidence.write_bytes(b"payload has been tampered with")
    f = {
        **_example_finding(),
        "evidence_ref": {"kind": "fixture_store", "value": str(evidence), "sha256": "c" * 64},
    }
    r = client.post("/api/findings/ingest", json=[f])
    assert r.status_code == 422
    assert "integrity mismatch" in r.json()["error"]
    assert client.get("/api/findings/red").json()["findings"] == []


def test_invalid_findings_rejected(client: TestClient):
    bad = [
        {**_example_finding(), "finding_id": "not-a-uuid"},
        {**_example_finding(), "finding_id": str(uuid.uuid4())},  # v4, not v5
        {**_example_finding(), "severity": "catastrophic"},
        {k: v for k, v in _example_finding().items() if k != "evidence_ref"},
        {**_example_finding(), "rule": "SEC-004"},  # rule must be RED-xxx
    ]
    for f in bad:
        r = client.post("/api/findings/ingest", json=[f])
        assert r.status_code == 422, f
    assert client.get("/api/findings/red").json()["findings"] == []
    assert client.post("/api/findings/ingest", json=[]).status_code == 422


def test_corpus_jsonl_shape_accepted_end_to_end(client: TestClient):
    corpora = pathlib.Path.home() / "Projects" / "raucle-agent-red" / "corpora" / "findings.jsonl"
    if not corpora.is_file():
        pytest.skip("red corpora not present")
    r = client.post(
        "/api/findings/ingest",
        content=corpora.read_text(),
        headers={"content-type": "text/plain"},
    )
    assert r.status_code == 200
    counts = client.get("/api/counts").json()
    n = counts["red"]["ingested"]
    assert n > 0
    assert counts["findings"]["total"] == len([f for f in client.get("/api/findings").json()]) + n


# ------------------------------------------------------- counting coherence
def test_counts_total_is_assurance_plus_red(client: TestClient):
    baseline = client.get("/api/counts").json()
    assurance_total = baseline["findings"]["total"]
    n = 5
    for f in [
        _example_finding(
            finding_id=str(uuid.uuid5(uuid.NAMESPACE_URL, f"r{i}")),
            severity=["info", "low", "medium", "high", "critical"][i],
        )
        for i in range(n)
    ]:
        assert client.post("/api/findings/ingest", json=[f]).status_code == 200
    counts = client.get("/api/counts").json()
    assert counts["findings"]["total"] == assurance_total + n
    assert counts["red"]["ingested"] == n
    assert sum(counts["red"]["by_severity"].values()) == n
    assert counts["triaged_findings"]["total"] == counts["findings"]["total"]
    lens = counts["findings"]["lens"]
    # the partition still closes with red folded in
    assert lens["open"] + lens["closed"] + lens["suppressed"] == counts["findings"]["total"]
    # info → unproven, high/critical → needs_investigation
    assert lens["needs_investigation"] >= 2
    board = client.get("/api/findings/board").json()
    assert sum(board["columns"].values()) == counts["findings"]["total"]
    red_rows = [f for f in board["findings"] if f["source"] == RED_SOURCE]
    assert len(red_rows) == n
    # board KPIs stay sourced from the shared counting module
    assert board["kpis"]["needs_investigation"] == lens["needs_investigation"]


# ----------------------------------------------------------- console copy
def test_console_red_copy_rewrite():
    text = CONSOLE_HTML.read_text()
    assert "Coming soon. Wave two of the suite; announcing later." not in text
    expected = (
        "Wave 2 in build. The gate fuzzer already runs against your policies; "
        "every attack it attempts is itself gated and receipted."
    )
    assert expected in text
    # the ingested-findings summary card reads the red slice and keeps every
    # render textContent-only (no innerHTML / innerText writes). It reads
    # the same-origin console proxy, never the add-in cross-origin (the
    # add-in sends no CORS headers by design).
    assert "'/api/assurance/findings/red'" in text
    assert "Ingested red findings" in text
    assert "red-mvp" in text
    js_window = text[
        text.index("function viewRed") : text.index(
            "/* ------------------------------------------------------------------ tenant pages"
        )
    ]
    assert "innerHTML" not in js_window
    assert "document.write" not in js_window
