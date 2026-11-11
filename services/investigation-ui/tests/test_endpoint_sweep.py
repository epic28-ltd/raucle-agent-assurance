"""Investigation-UI endpoint sweep: every route, happy plus 4xx failure paths.

Auditor story: the investigation board never hides failure — unknown runs,
receipts, findings and malformed ids all get explicit 4xx or escaped
'unknown' pages, triage validation is charset/enum-gated, offline verify
states an explicit unavailable verdict instead of fabricating one, and the
optional Langfuse source degrades honestly in every state.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import pathlib
import shutil
import sys

import pytest
from fastapi.testclient import TestClient

UI = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = UI.parents[1]

for _src in (
    REPO_ROOT / "packages" / "raucle-adapter" / "src",
    REPO_ROOT / "services" / "correlation" / "src",
    REPO_ROOT / "services" / "rules" / "src",
    UI / "src",
):
    sys.path.insert(0, str(_src))

from oaa_investigation_ui.app import (  # noqa: E402
    _findings_age_seconds,
    _triage_state_path,
    create_app,
)

DATA_DIR = UI / "demo_data"
ALLOW_HASH = "sha256:a3e29df11123ffc4c65fd50a5841d356b191a0fa85ff5b04fe970ed6f74379d5"
SYNTH_HASH = "sha256:" + "cd" * 32


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    d = tmp_path_factory.mktemp("ui-data")
    shutil.copytree(DATA_DIR, d, dirs_exist_ok=True)
    return d


@pytest.fixture(scope="module")
def client(data_dir: pathlib.Path) -> TestClient:
    return TestClient(create_app(data_dir))


def _fresh_client(data_dir: pathlib.Path) -> TestClient:
    return TestClient(create_app(data_dir))


def _first_finding_id(client: TestClient) -> str:
    board = client.get("/api/findings/board").json()
    return board["findings"][0]["id"]


def _first_run_id(client: TestClient) -> str:
    return client.get("/api/runs").json()[0]["run_id"]


# ------------------------------------------------------------------- runs ----


def test_unknown_run_id_is_404(client: TestClient) -> None:
    r = client.get("/api/runs/no-such-run")
    assert r.status_code == 404
    assert r.json() == {"error": "unknown run_id"}


def test_view_run_unknown_renders_escaped_not_blank(client: TestClient) -> None:
    r = client.get("/view/run/no-such-run<script>")
    assert r.status_code == 200
    assert "unknown run_id (escaped)" in r.text
    assert "<script>" not in r.text


def test_view_run_happy_renders_traces_and_findings(client: TestClient) -> None:
    r = client.get(f"/view/run/{_first_run_id(client)}")
    assert r.status_code == 200
    assert "&larr; runs" in r.text
    assert "findings" in r.text


def test_view_runs_lists_every_run(client: TestClient) -> None:
    r = client.get("/view/runs")
    assert r.status_code == 200
    assert f"/view/run/{_first_run_id(client)}" in r.text


# -------------------------------------------------------------- evidence ----


def test_unknown_receipt_is_404_json(client: TestClient) -> None:
    r = client.get(f"/api/receipts/{SYNTH_HASH}")
    assert r.status_code == 404
    assert r.json() == {"error": "unknown receipt"}


def test_jws_unknown_receipt_is_404_without_fabrication(client: TestClient) -> None:
    r = client.get(f"/api/receipts/{SYNTH_HASH}/jws")
    assert r.status_code == 404
    assert "no canonical envelope" in r.json()["error"]


def test_jws_happy_serves_the_verbatim_jws(client: TestClient) -> None:
    r = client.get(f"/api/receipts/{ALLOW_HASH}/jws")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/jwt")
    store_line = (
        (DATA_DIR / "evidence_store.jsonl")
        .read_text()
        .splitlines()[
            next(
                i
                for i, ln in enumerate((DATA_DIR / "evidence_store.jsonl").read_text().splitlines())
                if ALLOW_HASH in ln
            )
        ]
    )
    assert r.text == json.loads(store_line)["jws"]


def test_view_receipt_unknown_is_escaped(client: TestClient) -> None:
    r = client.get("/view/receipt/no-such<span>")
    assert r.status_code == 200
    assert "unknown receipt (escaped)" in r.text
    assert "<span>" not in r.text


def test_view_receipt_happy_shows_verify_button_not_jws_value(client: TestClient) -> None:
    r = client.get(f"/view/receipt/{ALLOW_HASH}")
    assert r.status_code == 200
    assert "Verify offline" in r.text
    assert "available for download" in r.text


def test_verify_receipt_unknown_states_unavailable_not_faked(client: TestClient) -> None:
    """A synthetic index row has no canonical envelope: the API returns 404
    with the explicit unavailable verdict, never a crypto verdict."""
    r = client.post(f"/api/receipts/{SYNTH_HASH}/verify")
    assert r.status_code == 404
    body = r.json()
    assert body["verification_status"] == "unavailable"
    assert body["checks_performed"] == []
    assert "no canonical envelope" in body["detail"]


def test_verify_receipt_happy_runs_real_verify(client: TestClient) -> None:
    r = client.post(f"/api/receipts/{ALLOW_HASH}/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["receipt_hash"] == ALLOW_HASH
    assert body["verification_status"] in ("valid", "invalid", "unknown_key")


def test_view_verify_unknown_is_explicit_not_blank(client: TestClient) -> None:
    r = client.post("/view/receipt/no-such/verify")
    assert r.status_code == 200
    assert "no canonical envelope" in r.text
    assert "offline classify not applicable" in r.text


def test_view_verify_happy_prints_verifier_summary(client: TestClient) -> None:
    r = client.post(f"/view/receipt/{ALLOW_HASH}/verify")
    assert r.status_code == 200
    assert "verifier output summary" in r.text
    assert ALLOW_HASH in r.text


# ---------------------------------------------------------------- triage ----


def test_triage_rejects_malformed_finding_ids(client: TestClient, data_dir: pathlib.Path) -> None:
    for bad in ("..escape", ".dotstart", "a" * 200, "$bad"):
        r = client.post(f"/api/findings/{bad}/triage", json={"state": "new"})
        assert r.status_code == 422, r.text
        assert r.json()["error"] == "malformed finding id"


def test_triage_unknown_finding_is_404(client: TestClient) -> None:
    r = client.post("/api/findings/not-a-real-finding/triage", json={"state": "new"})
    assert r.status_code == 404
    assert r.json() == {"error": "unknown finding id"}


def test_triage_rejects_states_outside_the_board_enum(client: TestClient) -> None:
    fid = _first_finding_id(client)
    r = client.post(f"/api/findings/{fid}/triage", json={"state": "done"})
    assert r.status_code == 422
    assert "state must be one of" in r.json()["error"]


def test_triage_happy_persists_sidecar_and_board_reflects_it(
    client: TestClient, data_dir: pathlib.Path
) -> None:
    fid = _first_finding_id(client)
    r = client.post(f"/api/findings/{fid}/triage", json={"state": "investigating"})
    assert r.status_code == 200
    assert r.json() == {"id": fid, "state": "investigating"}
    sidecar = json.loads((data_dir / "triage_state.json").read_text())
    assert sidecar[fid] == "investigating"
    board = client.get("/api/findings/board").json()
    assert board["findings"][0]["state"] == "investigating"
    # the canonical evidence store stays byte-identical (invariant 1)
    assert (data_dir / "evidence_store.jsonl").read_bytes() == (
        DATA_DIR / "evidence_store.jsonl"
    ).read_bytes()


# ---------------------------------------------------------------- ingest ----


def test_ingest_rejects_empty_and_invalid_bodies(client: TestClient) -> None:
    r = client.post("/api/findings/ingest", json=[])
    assert r.status_code == 422
    r = client.post(
        "/api/findings/ingest",
        content=b"not json",
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 422
    r = client.post("/api/findings/ingest", json={"findings": [{"severity": 42}]})
    assert r.status_code == 422
    r = client.post("/api/findings/ingest")
    assert r.status_code == 422  # no body at all


def test_ingest_happy_is_idempotent(client: TestClient) -> None:
    finding = json.loads((DATA_DIR / "red_findings.json").read_text())["findings"][0]
    first = client.post("/api/findings/ingest", json=[finding])
    assert first.status_code == 200, first.text
    assert first.json()["ingested"] is True
    again = client.post("/api/findings/ingest", json=[finding])
    assert again.status_code == 200
    # re-posting a run changes nothing (idempotent merge)
    assert again.json().get("added", first.json().get("added")) in (0, None)
    reds = client.get("/api/findings/red").json()
    assert reds["findings"]
    assert reds["source"]


# ----------------------------------------------------------- live traces ----


def test_live_traces_without_env_degrades_honestly(client: TestClient) -> None:
    r = client.get("/api/live/traces")
    body = r.json()
    assert body["available"] is False
    assert "skippable source" in body["reason"]


def test_live_traces_with_failing_source_names_the_error(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OAA_LANGFUSE_BASE_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("OAA_LANGFUSE_PUBLIC_KEY", "pk")
    monkeypatch.setenv("OAA_LANGFUSE_SECRET_KEY", "sk")

    def _boom(*a, **k):
        raise httpx.ConnectError("refused")

    import httpx  # noqa: PLC0415

    monkeypatch.setattr(httpx, "get", _boom)
    body = client.get("/api/live/traces").json()
    assert body["available"] is False
    assert "langfuse unavailable" in body["reason"]


def test_live_traces_success_projects_index_plane_only(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OAA_LANGFUSE_BASE_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("OAA_LANGFUSE_PUBLIC_KEY", "pk")
    monkeypatch.setenv("OAA_LANGFUSE_SECRET_KEY", "sk")

    class _Resp:
        def raise_for_status(self):
            return None

        def json(self):
            # the projection reads the traces key the service actually expects
            return {
                "self.data": [
                    {
                        "traceId": "trace-1",
                        "name": "run",
                        "timestamp": "2026-11-05T12:00:00Z",
                    }
                ]
                * 30
            }

    import httpx  # noqa: PLC0415

    monkeypatch.setattr(httpx, "get", lambda *a, **k: _Resp())
    body = client.get("/api/live/traces").json()
    assert body["available"] is True
    traces = body["traces"]
    assert len(traces) == 20  # capped at 20
    assert set(traces[0]) == {"trace_id", "name", "timestamp"}


# ---------------------------------------------------- OV-2 assurance packet ----


def _packet_module():
    """The generator's real code, imported by path exactly as the CLI does."""
    import importlib.util  # noqa: PLC0415

    path = REPO_ROOT / "services" / "assurance_packet" / "packet.py"
    spec = importlib.util.spec_from_file_location("oaa_assurance_packet", path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_assurance_packet_happy_is_the_generator_packet(
    tmp_path: pathlib.Path,
) -> None:
    module = _packet_module()
    d = tmp_path / "ui-data"
    shutil.copytree(DATA_DIR, d, dirs_exist_ok=True)
    r = _fresh_client(d).post("/assurance/packet")
    assert r.status_code == 200
    packet = r.json()
    assert packet == module.build_packet(d / "evidence_store.jsonl")
    assert packet["kind"] == "agent_assurance_packet"
    assert "does not establish legal or regulatory" in packet["guard"]


def test_assurance_packet_is_deterministic_across_calls(client: TestClient) -> None:
    a = client.post("/assurance/packet")
    b = client.post("/assurance/packet")
    assert a.status_code == b.status_code == 200
    assert a.content == b.content


def test_assurance_packet_declared_refs_change_the_packet(client: TestClient) -> None:
    plain = client.post("/assurance/packet").json()
    declared = client.post(
        "/assurance/packet",
        json={"capability_refs": ["cap:mcp/fs-write"], "governance_mapping": {"dora": ["DORA-1"]}},
    )
    assert declared.status_code == 200
    assert declared.json()["capability_refs"] == ["cap:mcp/fs-write"]
    assert declared.json()["governance_mapping"]["dora"] == ["DORA-1"]
    assert declared.json()["packet_content_sha256"] != plain["packet_content_sha256"]


def test_assurance_packet_bad_declared_refs_is_422_named(client: TestClient) -> None:
    r = client.post("/assurance/packet", json={"capability_refs": "not-a-list"})
    assert r.status_code == 422
    assert r.json()["error"] == "capability_refs must be a list of strings"


def test_assurance_packet_unknown_body_field_is_422_named(client: TestClient) -> None:
    r = client.post("/assurance/packet", json={"nonsense": []})
    assert r.status_code == 422
    assert "unknown declared-ref field(s): nonsense" in r.json()["error"]


def _client_minus_store(tmp_path: pathlib.Path) -> TestClient:
    """App built over a data dir whose evidence store then vanishes: the
    packet layer must see and name the absence, never fabricate."""
    d = tmp_path / "ui-data"
    shutil.copytree(DATA_DIR, d, dirs_exist_ok=True)
    tc = _fresh_client(d)
    (d / "evidence_store.jsonl").unlink()
    return tc


def test_assurance_packet_missing_store_is_404_named(tmp_path: pathlib.Path) -> None:
    client = _client_minus_store(tmp_path)
    r = client.post("/assurance/packet")
    assert r.status_code == 404
    assert "evidence store not found" in r.json()["error"]


def test_assurance_packet_tampered_store_is_422_named(
    tmp_path: pathlib.Path,
) -> None:
    d = tmp_path / "ui-data"
    shutil.copytree(DATA_DIR, d, dirs_exist_ok=True)
    store = d / "evidence_store.jsonl"
    lines = store.read_text().splitlines()
    rec = json.loads(lines[0])
    rec["jws"] = rec["jws"][:-2] + "xx"
    lines[0] = json.dumps(rec)
    store.write_text("\n".join(lines) + "\n")
    r = _fresh_client(d).post("/assurance/packet")
    assert r.status_code == 422
    assert "tampered" in r.json()["error"]


def test_assurance_summary_happy_is_textcontent_html(client: TestClient) -> None:
    r = client.get("/assurance/summary")
    assert r.status_code == 200
    body = r.text
    assert body.startswith("<!doctype html>")
    assert "does not establish legal or regulatory" in body
    assert "<script" not in body
    assert "onclick" not in body


def test_assurance_summary_missing_store_is_404(tmp_path: pathlib.Path) -> None:
    r = _client_minus_store(tmp_path).get("/assurance/summary")
    assert r.status_code == 404
    assert "evidence store not found" in r.json()["error"]


# ------------------------------------------------------------ unit helpers ----


def test_triage_state_path_refuses_escape(tmp_path: pathlib.Path, monkeypatch) -> None:
    """The sidecar path is confined to the data dir; a symlink escaping it
    raises rather than reading/writing outside."""
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    base = tmp_path / "data"
    base.mkdir()
    (base / "triage_state.json").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes the demo data dir"):
        _triage_state_path(base)


def test_findings_age_seconds_none_without_detected_at(monkeypatch) -> None:
    assert _findings_age_seconds({"id": "x"}) is None
    monkeypatch.setenv("TZ", "UTC")
    val = _findings_age_seconds({"id": "x", "detected_at": "2026-11-05T00:00:00+00:00"})
    assert val is not None
    assert val >= 0


# ------------------------------------------------------- EPIC P2.C fleet ----

FLEET_ARTIFACTS = {
    "gates": [
        {
            "gate_id": "gate-alpha",
            "board": {
                "kind": "findings_board",
                "findings": [
                    {
                        "id": "f1",
                        "rule": "RED-003",
                        "severity": "critical",
                        "verification_status": "pending",
                    },
                    {"id": "f2", "rule": "BEH-A", "severity": "low"},
                ],
            },
            "coverage": {"reported": 75},
            "baseline": {"status": "clean", "violations": []},
            "drilldown_url": "/view/runs",
        },
        {"gate_id": "gate-beta"},  # shipped nothing but its name: all ABSENT
    ]
}


def _fleet_reset(client: TestClient) -> None:
    r = client.delete("/api/fleet/rollup")
    assert r.status_code == 200


def test_fleet_rollup_empty_fleet_is_explicit(client: TestClient) -> None:
    _fleet_reset(client)
    r = client.get("/api/fleet/rollup")
    assert r.status_code == 200
    body = r.json()
    assert body["rollup"]["kind"] == "fleet_rollup"
    assert body["rollup"]["gates"] == []
    assert body["rollup"]["totals"]["gates"] == 0


def test_fleet_rollup_happy_is_deterministic_and_honest(client: TestClient) -> None:
    _fleet_reset(client)
    ing = client.post("/api/fleet/rollup", json=FLEET_ARTIFACTS)
    assert ing.status_code == 200
    assert ing.json() == {"ingested": True, "gates": 2}
    first = client.get("/api/fleet/rollup")
    again = client.get("/api/fleet/rollup")
    assert first.status_code == again.status_code == 200
    assert first.content == again.content  # deterministic output
    rollup = first.json()["rollup"]
    gates = {g["gate_id"]: g for g in rollup["gates"]}
    assert gates["gate-alpha"]["violations"] == 1
    assert gates["gate-alpha"]["coverage"] == 75  # as reported
    # gate-beta reported nothing: ABSENT, never zero
    for metric in ("violations", "drift", "unverified", "coverage"):
        assert gates["gate-beta"][metric] == "ABSENT"
    assert rollup["totals"]["violations"]["reported_total"] == 1
    assert rollup["totals"]["violations"]["absent_gates"] == ["gate-beta"]


def test_fleet_reingest_is_idempotent_per_gate(client: TestClient) -> None:
    _fleet_reset(client)
    client.post("/api/fleet/rollup", json=FLEET_ARTIFACTS)
    ing = client.post("/api/fleet/rollup", json={"gates": [{"gate_id": "gate-beta"}]})
    assert ing.status_code == 200
    assert ing.json()["gates"] == 2  # merge, not duplicate


def test_fleet_ingest_rejects_bad_artifacts_named(client: TestClient) -> None:
    for bad, msg in (
        (None, "must be a JSON array"),
        ([{"gate_id": "../escape"}], "gate_id"),
        ({"gates": [{"nonsense": 1}]}, "gate_id"),
        ({"gates": [{"gate_id": "ok", "drilldown_url": "http://evil"}]}, "relative in-app path"),
    ):
        r = client.post("/api/fleet/rollup", json=bad)
        assert r.status_code == 422, (bad, r.text)
        assert msg in r.json()["error"]


def test_fleet_baseline_surfaces_regressions_fleet_wide(client: TestClient) -> None:
    _fleet_reset(client)
    client.post(
        "/api/fleet/rollup",
        json={
            "gates": [
                {"gate_id": "gate-alpha", "baseline": {"status": "clean", "violations": []}},
                {
                    "gate_id": "gate-beta",
                    "baseline": {"status": "regressed", "violations": [{"rule": "F2-deny-step"}]},
                },
            ]
        },
    )
    r = client.get("/api/fleet/rollup")
    baseline = r.json()["baseline"]
    assert baseline["kind"] == "fleet_baseline"
    assert baseline["regressed_gates"] == ["gate-beta"]
    gates = {g["gate_id"]: g for g in baseline["gates"]}
    assert gates["gate-beta"]["violations"] == [{"rule": "F2-deny-step"}]
    missing = client.delete("/api/fleet/rollup")
    assert missing.status_code == 200
    baseline = client.get("/api/fleet/rollup").json()["baseline"]
    assert all(g["status"] == "ABSENT" for g in baseline["gates"]) or baseline["gates"] == []


def test_view_fleet_page_is_textcontent_only(client: TestClient) -> None:
    r = client.get("/view/fleet")
    assert r.status_code == 200
    text = r.text
    assert "textContent" in text
    assert ".innerHTML" not in text  # no DOM writes but textContent
    assert "onclick" not in text
    assert "<script" in text
    assert text.count("<script") == 1
    assert "/api/fleet/rollup" in text
    assert "ABSENT" in text  # absence is a first-class rendered state


def test_fleet_sidecar_does_not_touch_evidence_store(
    client: TestClient, data_dir: pathlib.Path
) -> None:
    _fleet_reset(client)
    client.post("/api/fleet/rollup", json=FLEET_ARTIFACTS)
    assert (data_dir / "fleet_gates.json").is_file()
    assert (data_dir / "evidence_store.jsonl").read_bytes() == (
        DATA_DIR / "evidence_store.jsonl"
    ).read_bytes()
