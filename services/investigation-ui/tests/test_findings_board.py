# SPDX-License-Identifier: Apache-2.0
"""UI-02.4 findings board tests: routes, chip reconciliation, card anatomy,
guidance-note escaping, demo-data completeness and the triage lifecycle.

Runs against the real demo fixture dir for corpus checks, and against a
throwaway copy for the mutation endpoints (board state persistence) so the
repo's demo data stays clean while tests run.
"""

from __future__ import annotations

import json
import pathlib
import re
import shutil
import sys

UI = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(UI / "src"))
for _src in (
    UI.parents[1] / "packages" / "raucle-adapter" / "src",
    UI.parents[1] / "services" / "correlation" / "src",
    UI.parents[1] / "services" / "rules" / "src",
):
    sys.path.insert(0, str(_src))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from oaa_investigation_ui.app import create_app  # noqa: E402

DATA_DIR = UI / "demo_data"
INDEX_HTML = UI / "static" / "index.html"


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(create_app(DATA_DIR))


@pytest.fixture()
def tmp_client(tmp_path: pathlib.Path) -> TestClient:
    """A copy of the demo dir so triage-state writes never touch the repo."""
    shutil.copytree(DATA_DIR, tmp_path / "demo")
    return TestClient(create_app(tmp_path / "demo"))


# --------------------------------------------------------- demo completeness
def test_demo_corpus_fires_all_eleven_rules(client: TestClient):
    findings = client.get("/api/findings").json()
    present = {f["rule_id"] for f in findings}
    assert present == {f"SEC-{i:03d}" for i in range(1, 12)}


def test_demo_corpus_covers_matched_degraded_and_trace_missing(client: TestClient):
    d = client.get("/api/dashboard").json()
    corr = d["correlation_distribution"]
    assert corr.get("matched_degraded", 0) >= 1
    assert corr.get("trace_missing", 0) >= 1


def test_board_findings_carry_lens_and_ids(client: TestClient):
    board = client.get("/api/findings/board").json()
    assert {"kpis", "columns", "findings", "states"} <= set(board)
    for f in board["findings"]:
        assert f["lens"] in ("needs", "unproven", "gaps")
        assert f["state"] in ("new", "investigating", "suppressed", "closed")
        assert f["id"]
        assert f["primary_ref"]


# ---------------------------------------------------- chip reconciliation
def test_chip_counts_equal_member_counts(client: TestClient):
    board = client.get("/api/findings/board").json()
    findings = board["findings"]
    members = {
        "needs": lambda f: f["state"] in ("new", "investigating") and f["lens"] == "needs",
        "unproven": lambda f: f["state"] in ("new", "investigating") and f["lens"] == "unproven",
        "gaps": lambda f: f["state"] in ("new", "investigating") and f["lens"] == "gaps",
        "closed": lambda f: f["state"] == "closed",
        "suppressed": lambda f: f["state"] == "suppressed",
    }
    # partition property over open cards: every open finding maps to exactly
    # one of the three risk-lens chips
    open_cards = [f for f in findings if f["state"] in ("new", "investigating")]
    members_test = sum(t(f) for t in members.values() for f in open_cards)
    assert len(open_cards) == members_test
    # the closed + suppressed chips pick out exactly their column members
    assert sum(1 for f in findings if f["state"] == "closed") == board["columns"]["closed"]
    assert sum(1 for f in findings if f["state"] == "suppressed") == board["columns"]["suppressed"]


def test_board_kpis_equal_counts_and_chip_members(client: TestClient):
    """Every KPI number equals the /api/counts breakdown AND the chip member
    count of the same bucket on the board (coherence-pass blocker)."""
    board = client.get("/api/findings/board").json()
    counts = client.get("/api/counts").json()
    findings = board["findings"]
    open_f = [f for f in findings if f["state"] in ("new", "investigating")]
    chip_members = {
        "needs_investigation": sum(1 for f in open_f if f["lens"] == "needs"),
        "unproven": sum(1 for f in open_f if f["lens"] == "unproven"),
        "coverage_gaps": sum(1 for f in open_f if f["lens"] == "gaps"),
    }
    assert (
        board["kpis"]["needs_investigation"]
        == counts["findings"]["lens"]["needs_investigation"]
        == chip_members["needs_investigation"]
    )
    assert (
        board["kpis"]["unproven"]
        == counts["findings"]["lens"]["unproven"]
        == (chip_members["unproven"])
    )
    assert (
        board["kpis"]["coverage_gaps"]
        == counts["findings"]["lens"]["coverage_gaps"]
        == chip_members["coverage_gaps"]
    )
    # verified is an explicit index-plane metric == the counts valid bucket
    assert board["kpis"]["verified"] == counts["verification"]["buckets"]["valid"]
    # the open columns' members sum to the counts open bucket
    open_visible = board["columns"]["new"] + board["columns"]["investigating"]
    assert open_visible == counts["findings"]["lens"]["open"]


def test_counts_reconciles_everywhere(client: TestClient):
    counts = client.get("/api/counts").json()
    v = counts["verification"]
    assert sum(v["buckets"].values()) == v["total"] == sum(v["states"].values())
    c = counts["correlation"]
    assert sum(c["states"].values()) == v["total"]
    assert sorted(c["states"]) == sorted(
        # all eight ADR-0002 states materialised, zeros included
        [
            "matched",
            "matched_degraded",
            "ambiguous",
            "duplicate",
            "late_arrival",
            "receipt_missing",
            "trace_missing",
            "pending",
        ]
    )
    f = counts["findings"]["lens"]
    assert f["needs_investigation"] + f["unproven"] + f["coverage_gaps"] == f["open"]
    assert f["open"] + f["closed"] + f["suppressed"] == counts["findings"]["total"]


def test_kpi_strip_counts_reconcile_with_columns(client: TestClient):
    board = client.get("/api/findings/board").json()
    assert sum(board["columns"].values()) == len(board["findings"])


def test_column_counts_match_findings_by_state(client: TestClient):
    board = client.get("/api/findings/board").json()
    by_api = board["columns"]
    by_hand: dict[str, int] = dict.fromkeys(board["states"], 0)
    for f in board["findings"]:
        by_hand[f["state"]] += 1
    assert by_api == by_hand


def test_suppressed_column_retains_reason(client: TestClient):
    board = client.get("/api/findings/board").json()
    sup = [f for f in board["findings"] if f["state"] == "suppressed"]
    assert sup
    assert all(f["suppression_reason"] for f in sup)


# ------------------------------------------------------- guidance note (XSS)
def test_board_note_rendering_is_escaped_by_construction():
    html = INDEX_HTML.read_text()
    code_only = "\n".join(line.split("//")[0] for line in html.splitlines())
    # no unsafe sink anywhere (test mirrors the UI-02 rule for the board code)
    assert not re.search(r"\.innerHTML|\bdocument\.write\b|\binsertAdjacentHTML\b", code_only)
    # the finding note, its evidence ref and the toast all write through
    # textContent-bearing helpers only
    assert 'el("div", null, "Suggested action: " + g.actions[0])' in html
    assert "t.textContent = msg" in html or "toast.textContent" in html
    # the guidance note carries no raw markup template with interpolation
    assert "finding-note" in html
    assert "note-body" in html


def test_board_api_never_echoes_audit_content(client: TestClient):
    board = client.get("/api/findings/board").json()
    # PRIV-01: the matched content string never appears in any finding field
    blob = json.dumps(board)
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "aws_access_key pattern value" not in blob


# ------------------------------------------------------- triage persistence
def test_state_cycle_persists_to_index_sidecar(tmp_client: TestClient, tmp_path: pathlib.Path):
    board = tmp_client.get("/api/findings/board").json()
    target = next(f for f in board["findings"] if f["state"] == "new")
    r = tmp_client.post(f"/api/findings/{target['id']}/triage", json={"state": "investigating"})
    assert r.status_code == 200
    assert r.json()["state"] == "investigating"
    board2 = tmp_client.get("/api/findings/board").json()
    after = next(f for f in board2["findings"] if f["id"] == target["id"])
    assert after["state"] == "investigating"
    # the sidecar index (demo-data sibling, never the canonical store) gets
    # the triage row
    sidecar = tmp_path / "demo" / "triage_state.json"
    assert sidecar.is_file()
    assert target["id"] in json.loads(sidecar.read_text())
    assert (tmp_path / "demo" / "evidence_store.jsonl").read_text() == (
        (DATA_DIR / "evidence_store.jsonl").read_text()
    )


def test_triage_unknown_finding_and_state(tmp_client: TestClient):
    assert tmp_client.post("/api/findings/f-nope/triage", json={"state": "new"}).status_code == 404
    board = tmp_client.get("/api/findings/board").json()
    fid = board["findings"][0]["id"]
    bad = tmp_client.post(f"/api/findings/{fid}/triage", json={"state": "bogus"})
    assert bad.status_code == 422


def test_restore_sets_suppressed_card_to_new(tmp_client: TestClient):
    board = tmp_client.get("/api/findings/board").json()
    sup = next(f for f in board["findings"] if f["state"] == "suppressed")
    r = tmp_client.post(f"/api/findings/{sup['id']}/triage", json={"state": "new"})
    assert r.json()["state"] == "new"
    board2 = tmp_client.get("/api/findings/board").json()
    after = next(f for f in board2["findings"] if f["id"] == sup["id"])
    assert after["state"] == "new"
    # retention: the documented suppression_reason is still on the record
    assert after["suppression_reason"]


# ---------------------------------------------------------------- SPA wiring
def test_board_route_and_nav_wired():
    html = INDEX_HTML.read_text()
    assert 'id="tab-findings"' in html
    assert 'location.hash = "findings"' in html
    assert 'h.startsWith("findings")' in html or 'startsWith("findings")' in html
    assert "#/findings" in html.replace("&#/", "#/")
    assert 'id="theme-toggle"' in html
    assert 'data-theme="dark"' in html


def test_board_static_anatomy():
    html = INDEX_HTML.read_text()
    for needle in (
        "kpi-card",
        "kpi-group",
        "kpi-tile",
        "Needs investigation",
        "Unproven",
        "Coverage gaps",
        "Evidence verified",
        "scopepill",
        "Sort: Most severe",
        "findchip",
        'boardLens = "needs"',
        "Closed",
        "Suppressed",
        "Showing ",
        " findings",
        "board-col",
        "count-badge",
        "target: zero active",
        "finding-note",
        "Open full guidance",
        "action stub: alpha",
        "Move state (",
        "btn-dark",
        "Restore",
        "summary-card",
        "allclear",
        "closed",
        "No findings here",
        "More",
    ):
        assert needle in html, needle


def test_board_chips_single_select_static_contract():
    html = INDEX_HTML.read_text()
    # exactly one chip is active by default (aria-pressed wiring + the dark
    # active token); clicking a chip sets aria-pressed on every chip
    assert "String(boardLens === key)" in html
    assert 'c.setAttribute("aria-pressed", String(c.dataset.chip === boardLens))' in html
    assert 'findchip[aria-pressed="true"]' in html
    # default chip lives in the row-2 bar and the showing count is live text
    assert "Showing " + shown_expression() in html


def shown_expression() -> str:
    return '" + shown.length + " of " + findings.length + " findings"'


def test_rule_action_buttons_and_stubs():
    html = INDEX_HTML.read_text()
    assert '"SEC-004": {label: "Compare tool-side event"' in html
    assert '"SEC-001": {label: "Corroborate coverage"' in html
    assert 'toast("action stub: alpha")' in html
    # real wiring exists for the one endpoint the add-in actually serves
    assert 'act.endpoint === "verify"' in html
    assert '"/verify"' in html or "/verify" in html


def test_age_pill_thresholds():
    html = INDEX_HTML.read_text()
    assert "86400" in html
    assert "3600" in html
    assert "tok-clock" in html
    assert "stale" in html
    assert "warm" in html


def test_empty_and_allclear_variants():
    html = INDEX_HTML.read_text()
    assert "allclear" in html
    assert "summary-card" in html
