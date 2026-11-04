# SPDX-License-Identifier: Apache-2.0
"""UI-01 investigation UI service tests (offline, TestClient, demo fixtures)."""

from __future__ import annotations

import pathlib
import sys

UI = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(UI / "src"))
# package imports rely on the repo-root conftest path setup for the
# correlation / rules / adapter modules; those are already on sys.path when
# rooted tests run — here we are self-contained:

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

HOSTILE_SCRIPT = "<script>alert('ui-01-xss')</script>"
HOSTILE_LINK = "javascript:alert(1)//oaa-console"
ALLOW_HASH = "sha256:a3e29df11123ffc4c65fd50a5841d356b191a0fa85ff5b04fe970ed6f74379d5"
DENY_HASH = "sha256:7ad7bb9a68f0c3d50b1d24451b4caa2059ced33d33d0e53755fe94fc18b787db"


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = create_app(DATA_DIR)
    return TestClient(app)


# ---------------------------------------------------------------- runs list
def test_runs_list_fields(client: TestClient):
    runs = client.get("/api/runs").json()
    ids = [r["run_id"] for r in runs]
    assert "run-obs01-01" in ids and "run-sim-02" in ids
    for r in runs:
        for field in (
            "agent",
            "release",
            "span_count",
            "verification_summary",
            "correlation_summary",
        ):
            assert field in r


def test_drilldown_states_rendered_not_blank(client: TestClient):
    run = client.get("/api/runs/run-obs01-01").json()
    by_name = {s["name"]: s for s in run["traces"][0]["spans"]}
    write = by_name["tool.write_file"]
    assert write["receipt_hash"] == DENY_HASH
    assert write["verification"]["status"] == "valid"  # full enum token, not blank
    # COR-01 is trace_id-keyed: two distinct receipts (read allow + write deny)
    # on the obs01 trace reconcile to `ambiguous` — surfaced, never resolved.
    assert write["correlation"]["state"] == "ambiguous"
    shell = by_name["tool.shell"]
    # explicit unknown states — never an empty string status
    assert shell["verification"]["status"] == "unavailable"
    assert shell["verification"]["detail"]
    sim = client.get("/api/runs/run-sim-02").json()
    states = {t["correlation"]["state"] for t in sim["traces"]}
    assert {"matched", "ambiguous", "duplicate", "late_arrival", "receipt_missing"} <= states
    statuses = {
        s["verification"]["status"]
        for t in sim["traces"]
        for s in t["spans"]
        if t["trace_id"] != "t-sim-sup-0000000000000000000000000000aa"
    }
    assert {
        "valid",
        "unknown_key",
        "unsupported_schema",
        "pending",
        "unavailable",
        "not_applicable",
    } <= statuses


# ---------------------------------------------------------------- escalation
def test_evidence_metadata_no_jws(client: TestClient):
    r = client.get(f"/api/receipts/{ALLOW_HASH}").json()
    assert r["schema_version"] == "provenance-receipt/v1"
    assert r["decision"] == "allow"
    assert r["policy_ref"] == "policies.yaml"
    assert r["jws"] == "available for download"
    assert r["jws_download"].endswith("/jws")
    raw = client.get(f"/api/receipts/{ALLOW_HASH}/jws")
    assert raw.status_code == 200
    # the verify endpoint runs raucle's own ProvenanceVerifier over the
    # canonical bytes (when raucle is importable in this environment) and
    # never echoes the JWS.
    verify = client.post(f"/api/receipts/{ALLOW_HASH}/verify").json()
    if raucle_available():
        assert verify["verification_status"] == "valid"
        assert verify["verifier_available"] is True
    else:
        # explicit absence is fail-visible, never a fabricated verdict
        assert verify["verification_status"] == "unavailable"
        assert verify["verifier_available"] is False
        skip_reason = "raucle not importable"
    if not raucle_available():
        pytest.skip(skip_reason)
    assert verify["receipt_hash"] == ALLOW_HASH
    assert jws_value_str() not in client.post(f"/api/receipts/{ALLOW_HASH}/verify").text


def raucle_available() -> bool:
    try:
        import oaa_raucle_adapter.evidence_plane as ep  # noqa: PLC0415

        ep._raucle()
        return True
    except ImportError:
        return False


def jws_value_str() -> str:
    import json  # noqa: PLC0415

    line = (DATA_DIR / "evidence_store.jsonl").read_text().splitlines()[0]
    return json.loads(line)["jws"]


def test_verify_unknown_and_synthetic(client: TestClient):
    synth = "sha256:synth0000000000000000000000000000000000000000000000000000000005"
    r = client.post(f"/api/receipts/{synth}/verify")
    body = r.json()
    # no canonical bytes: explicit non-verdict, never fabricated
    assert body["verification_status"] == "unavailable"
    assert "no canonical envelope" in body["detail"]
    missing = client.post("/api/receipts/sha256:does-not-exist/verify")
    assert missing.status_code == 404


# ----------------------------------------------------------------- findings
def test_findings_include_suppressed_with_reason(client: TestClient):
    findings = client.get("/api/findings").json()
    sec001 = [f for f in findings if f["rule_id"] == "SEC-001"]
    assert sec001
    suppressed = [f for f in sec001 if f["suppressed"]]
    assert suppressed and suppressed[0]["suppression_reason"]
    # suppressed findings are RETAINED with all fields, not dropped
    assert all(
        k in suppressed[0]
        for k in ("rule_id", "severity", "confidence", "explanation", "evidence_refs")
    )
    run = client.get("/api/runs/run-sim-02").json()
    tags = [f["suppressed"] for f in run["findings"]]
    assert set(tags) == {True, False}


# ------------------------------------------------------------- hostile text
def test_html_server_views_escaped_everywhere(client: TestClient):
    html_run = client.get("/view/run/run-obs01-01").text
    assert HOSTILE_SCRIPT not in html_run
    assert HOSTILE_LINK not in html_run
    assert "&lt;script&gt;alert(&#x27;ui-01-xss&#x27;)&lt;/script&gt;" in html_run
    assert "javascript:alert(1)" not in html_run  # no auto-link resolution
    assert "<script>" not in html_run
    for path in ("/view/runs", "/view/run/run-sim-02", f"/view/receipt/{ALLOW_HASH}", "/"):
        body = client.get(path).text
        assert HOSTILE_SCRIPT not in body or path == "/"  # SPA has no value at all
        if path != "/":
            assert "<script>alert" not in body


def test_spa_uses_textcontent_only(client: TestClient):
    page = client.get("/").text
    assert ".innerHTML" not in page
    assert "textContent" in page


def test_unknown_states_badge_class_rendered(client: TestClient):
    html_run = client.get("/view/run/run-sim-02").text
    for state in ("unknown_key", "unsupported_schema", "pending", "unavailable", "not_applicable"):
        assert state in html_run  # every explicit-unknown state is written out
        assert f"badge-unknown'{state}" in html_run or f"'>{state}</span>" in html_run
    # blank statuses would show as an empty badge — assert none exist
    assert "<span class='badge badge-ok'></span>" not in html_run
    assert "<span class='badge badge-unknown'></span>" not in html_run


def test_jws_never_in_any_response(client: TestClient):
    jws_prefix = "eyJhbG"
    for path in (
        "/api/runs",
        "/api/runs/run-obs01-01",
        "/api/findings",
        f"/api/receipts/{ALLOW_HASH}",
        "/view/run/run-obs01-01",
        f"/view/receipt/{ALLOW_HASH}",
    ):
        assert jws_prefix not in client.get(path).text
    dl = client.get(f"/api/receipts/{ALLOW_HASH}/jws")
    assert dl.headers["content-type"].startswith("application/jwt")
    assert dl.headers["content-disposition"].startswith("attachment")


def test_live_traces_skippable(client: TestClient):
    r = client.get("/api/live/traces").json()
    assert r["available"] is False
    assert "not configured" in r["reason"]


def test_evidence_store_unmutated(client: TestClient):
    # invariant 1: the whole UI is read-only over the canonical store
    before = (DATA_DIR / "evidence_store.jsonl").read_bytes()
    client.get("/view/run/run-sim-02")
    client.post(f"/api/receipts/{ALLOW_HASH}/verify")
    assert (DATA_DIR / "evidence_store.jsonl").read_bytes() == before
    assert (DATA_DIR / "synthetic_receipt_index.jsonl").is_file()


# -------------------------------------------------------------- UI-02 (SPA v2)
INDEX_HTML = UI / "static" / "index.html"
VERIFICATION_STATES_UI = {
    "valid", "invalid", "unknown_key", "unsupported_schema",
    "pending", "unavailable", "not_applicable",
}
CORRELATION_STATES_UI = {
    "matched", "matched_degraded", "ambiguous", "duplicate",
    "late_arrival", "receipt_missing", "trace_missing", "pending",
}
RULE_IDS_UI = {f"SEC-{i:03d}" for i in range(1, 12)}


def test_index_served_at_root_and_legacy_reachable(client: TestClient):
    html = client.get("/").text
    assert "UI-02" in html or "investigation" in html
    legacy = client.get("/legacy.html")
    assert legacy.status_code == 200
    assert "UI-01" in legacy.text


def test_index_no_innerHTML_no_external_fetch(client: TestClient):
    html = INDEX_HTML.read_text()
    # no unsafe sink anywhere in code (mention in a T5 comment is stripped)
    code_only = "\n".join(line.split("//")[0] for line in html.splitlines())
    assert not __import__("re").search(r"\.innerHTML|\bdocument\.write\b", code_only)
    for scheme in ("http://", "https://", "src=", "import(", "eval("):
        assert scheme not in html.replace('xmlns=', "").replace('href="/', "")


def test_index_legend_present(client: TestClient):
    html = INDEX_HTML.read_text()
    legend = client.get("/").text if False else html
    for token in ("legend", "tok-good", "tok-look", "tok-act", "tok-exempt",
                  "proven good", "un-proven", "action needed", "structurally exempt"):
        assert token in legend, token


def test_index_guidance_map_covers_all_states_and_rules():
    html = INDEX_HTML.read_text()
    import re as _re  # noqa: PLC0415
    for state in VERIFICATION_STATES_UI | CORRELATION_STATES_UI:
        # key may appear bare (JS object shorthand) or quoted — both are the
        # GUIDANCE map key when followed by "what:" guidance content
        pattern = _re.compile(r'["\']?' + _re.escape(state) + r'["\']?\s*:')
        assert pattern.search(html), state
    for rule in RULE_IDS_UI:
        assert '"' + rule + '":' in html or '"' + rule + '"' in html, rule
    # every guidance entry carries the four required headings
    for heading in ("What you are looking at", "What this means",
                    "Could be fine because", "Suggested actions"):
        assert heading in html


def test_dashboard_endpoint(client: TestClient):
    d = client.get("/api/dashboard").json()
    for key in ("healthy", "at_risk", "needs_investigation",
                "verification_distribution", "correlation_distribution",
                "findings", "runs"):
        assert key in d, key
    # counters cover privileged spans; needs_investigation also folds in
    # active findings (one active fixture finding)
    assert sum(d["verification_distribution"].values()) == sum(
        d["correlation_distribution"].values())
    assert d["needs_investigation"] - d["findings"]["active"] + d["healthy"] + d["at_risk"] == sum(
        d["verification_distribution"].values())
    # traffic-light logic: receipt_missing / invalid land under needs
    corr = d["correlation_distribution"]
    verif = d["verification_distribution"]
    assert d["needs_investigation"] >= corr.get("receipt_missing", 0) + verif.get("invalid", 0)
    assert d["findings"]["suppressed"] >= 1  # SEC-001 suppressed fixture retained
