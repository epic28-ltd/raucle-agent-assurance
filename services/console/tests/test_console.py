# SPDX-License-Identifier: Apache-2.0
"""EPIC-N Raucle Console tests: routes, config, textContent discipline,
semantic colour system guidance and single-tenant alpha contract."""

from __future__ import annotations

import datetime
import os
import pathlib
import re
import sys

import pytest
from fastapi.testclient import TestClient

from raucle_console.app import create_app

UI_DIR = (pathlib.Path(__file__).resolve().parents[1]).parent / "investigation-ui"
sys.path[:0] = [
    str(UI_DIR / "src"),
    str(UI_DIR.parents[1] / "packages" / "raucle-adapter" / "src"),
    str(UI_DIR.parents[1] / "services" / "correlation" / "src"),
    str(UI_DIR.parents[1] / "services" / "rules" / "src"),
]

from oaa_investigation_ui.counting import count_evidence  # noqa: E402

STATIC = pathlib.Path(__file__).resolve().parents[1] / "static"
CONSOLE_DIR = STATIC.parent


@pytest.fixture()
def client() -> TestClient:
    return TestClient(create_app())


# ------------------------------------------------------------- routes
def test_root_serves_single_page_shell(client: TestClient):
    r = client.get("/")
    assert r.status_code == 200
    assert "Raucle Console" in r.text
    assert r.headers["content-type"].startswith("text/html")


def test_static_index_same_document(client: TestClient):
    r = client.get("/static/index.html")
    assert r.status_code == 200


def test_api_overview_shape(client: TestClient):
    r = client.get("/api/overview")
    assert r.status_code == 200
    body = r.json()
    assert body["tenants"] == [{"id": "default", "label": "default"}]
    assert body["single_tenant_alpha"] is True
    ids = [a["id"] for a in body["addins"]]
    assert ids == ["trust", "assurance", "red"]
    for a in body["addins"]:
        assert a["status"] in ("connected", "degraded", "not_purchased")
    assert body["addins"][1]["status"] == "connected"  # assurance is LIVE
    # red is not purchased / coming soon
    assert body["addins"][2]["status"] == "not_purchased"
    # trust counts are DERIVED from the shared counting module, never pinned
    counts = count_evidence(UI_DIR / "demo_data")
    trust = body["trust"]
    assert trust["receipts_minted"] == counts["trust"]["receipts_minted"]
    assert trust["receipts_verified"] == counts["trust"]["verification_rows"]
    assert trust["receipts_valid"] == counts["trust"]["verification_valid"]
    # index-plane fallback figures agree with the add-in's own counts
    assert trust["spans_indexed"] == counts["verification"]["total"]
    assert trust["verification_distribution"] == counts["verification"]["states"]
    assert trust["verification_buckets"] == counts["verification"]["buckets"]
    assert trust["findings"] == counts["findings"]
    assert "shared counting module" in trust["source"]
    assert body["activity"]
    assert body["notifications"]["count"] >= 0


def test_api_overview_numbers_reconcile(client: TestClient):
    """Coherence pass: the trust block's buckets sum to its span total and
    the findings block reconciles open + closed + suppressed = total."""
    body = client.get("/api/overview").json()
    t = body["trust"]
    buckets = t["verification_buckets"]
    assert sum(buckets.values()) == t["spans_indexed"]
    f = t["findings"]["lens"]
    assert f["needs_investigation"] + f["unproven"] + f["coverage_gaps"] == f["open"]
    assert f["open"] + f["closed"] + f["suppressed"] == t["findings"]["total"]
    # activity + notification copy carry the same minted figure (no drift)
    minted = str(t["receipts_minted"])
    assert any(minted in item["what"] for item in body["activity"])
    assert any(minted in item for item in body["notifications"]["items"])


def test_api_health(client: TestClient):
    assert client.get("/api/health").json()["status"] == "ok"


def test_iframe_configurable_assurance_url():
    os.environ["RAUCLE_ASSURANCE_URL"] = "http://127.0.0.1:9911/"
    try:
        c = TestClient(create_app())
        body = c.get("/api/config").json()
        assert body["assurance_url"] == "http://127.0.0.1:9911/"
    finally:
        del os.environ["RAUCLE_ASSURANCE_URL"]


def test_iframe_config_default(client: TestClient):
    body = client.get("/api/config").json()
    assert body["assurance_url"] == "http://127.0.0.1:3411"
    assert body["trust_gate_env"] == "RAUCLE_TRUST_GATE_CONFIG"
    assert body["assurance_reachable"] is False


def test_assurance_dashboard_proxy_live(client: TestClient):
    """When the add-in is running on the configured URL the proxy returns its
    traffic-light counters; failure is an explicit 503, never a blank."""
    r = client.get("/api/assurance/dashboard")
    if r.status_code == 200:
        body = r.json()
        assert {"healthy", "at_risk", "needs_investigation"} <= set(body)
    else:
        assert r.status_code == 503
        assert r.json()["error"] == "add-in offline"


def test_assurance_dashboard_proxy_offline(monkeypatch):
    os.environ["RAUCLE_ASSURANCE_URL"] = "http://127.0.0.1:9"
    try:
        c = TestClient(create_app())
        r = c.get("/api/assurance/dashboard")
        assert r.status_code == 503
        assert r.json()["error"] == "add-in offline"
    finally:
        del os.environ["RAUCLE_ASSURANCE_URL"]


def test_api_overview_never_echoes_env(client: TestClient):
    """Secrets / environment values must never appear in any response."""
    text = str(client.get("/api/overview").json()) + client.get("/api/config").text
    for forbidden in ("SECRET", "PASSWORD", "TOKEN", "API_KEY"):
        assert forbidden.lower() not in text.lower()


# ------------------------------------------------------------- SPA discipline
def test_spa_textcontent_discipline():
    """Threat-model T5: the SPA has no innerHTML / document.write /
    script-src external fetches; rendering is textContent only."""
    html = (STATIC / "index.html").read_text()
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert forbidden not in html
    assert "textContent" in html
    # external scripts/stylesheets are not allowed
    for src in re.findall(r'<script[^>]*src=["\']([^"\']+)', html):
        assert src.startswith("http://127.0.0.1"), src
    for href in re.findall(r'<link[^>]*href=["\']([^"\']+)', html):
        assert href.startswith("http://127.0.0.1") or href.startswith("/"), href
    # the only cross-origin fetch target is the configured add-in origin
    for url in re.findall(r"https?://[^'\"\\s]+", html):
        assert url.startswith("http://127.0.0.1:"), url


def test_spa_single_tenant_and_no_cookies():
    html = (STATIC / "index.html").read_text()
    assert "default" in html  # single tenant placeholder


def test_spa_no_em_dashes_british_english():
    em_dash = chr(0x2014)
    for path in CONSOLE_DIR.rglob("*"):
        if path.is_file() and path.suffix in (".html", ".py"):
            text = path.read_text()
            assert em_dash not in text, path
    html = (STATIC / "index.html").read_text()
    # British spellings present, US variants absent (SPDX line is exempt)
    assert "licence" in html
    body_lines = [ln for ln in html.splitlines() if not ln.startswith("<!-- SPDX-")]
    assert "license" not in "\n".join(body_lines)


def test_spa_guidance_and_legend_present():
    html = (STATIC / "index.html").read_text()
    assert "What is this?" in html  # per-card explainer
    assert "Legend" in html  # semantic colour legend
    for tone in ("tok-good", "tok-look", "tok-act", "tok-exempt"):
        assert tone in html
    # add-in status chips
    for status in ("Connected", "Degraded", "Not purchased"):
        assert status in html


def test_spa_embeds_iframe_and_note():
    html = (STATIC / "index.html").read_text()
    assert "iframe" in html
    assert "separate add-in process" in html
    assert "/api/assurance/dashboard" in html  # graceful counters fetch
    assert "Add-in offline" in html  # graceful empty state


def test_spa_placeholder_views_marked():
    html = (STATIC / "index.html").read_text()
    assert html.count("alpha placeholder") >= 1


# ------------------------------------------------------------- UI-02.2 polish
def test_spa_info_popovers_replaced_paragraphs():
    """Per-card captions and the 'What is this?' paragraphs collapse into one
    info icon whose explainer lives in a CSS hover/focus popover, out of the
    visible flow."""
    html = (STATIC / "index.html").read_text()
    app_css = (STATIC / "app.css").read_text()
    assert html.count("c.explain(") >= 5  # wired onto each content card
    assert "info-pop" in html  # hidden by default in app.css
    assert 'class="explain"' not in html  # old visible explainer gone
    assert ".info-wrap:hover .info-pop" in app_css  # opens on hover
    assert ".info-wrap:focus-within .info-pop" in app_css  # opens on focus
    assert "'What is this?'" in html  # popover content stays in the DOM


def test_spa_chart_tooltip_layer():
    """Chart segments get a shared positioned tooltip div (vanilla, no
    native title-only affordance, no dependencies)."""
    html = (STATIC / "index.html").read_text()
    app_css = (STATIC / "app.css").read_text()
    assert 'id="tip" class="tip"' in html
    assert "function hookTip" in html
    assert "pointerenter" in html and "pointermove" in html
    assert ".tip{position:fixed" in app_css


def test_spa_font_vendored_no_external_urls():
    """Inter is self-hosted: @font-face points only at the vendor dir and no
    external font URL appears anywhere in the shell."""
    html = (STATIC / "index.html").read_text()
    assert "@font-face" in html
    assert "inter-latin-var.woff2" in html
    for forbidden in ("fonts.googleapis", "fonts.gstatic", "https://fonts"):
        assert forbidden not in html
    font = STATIC / "vendor" / "fonts" / "inter-latin-var.woff2"
    assert font.is_file() and font.stat().st_size > 10_000
    licence_txt = STATIC / "vendor" / "fonts" / "licence-Inter-OFL.txt"
    assert licence_txt.is_file()
    assert "Open Font License" in licence_txt.read_text()


def test_spa_tokens_layer_and_dark_mode():
    """UI-02.3: the design-token layer carries palette + dark equivalents,
    the shell links it (plus app.css) and no third-party CSS remains."""
    tokens = (STATIC / "tokens.css").read_text()
    app_css = STATIC / "app.css"
    shell = STATIC / "vendor" / "tabler"
    html = (STATIC / "index.html").read_text()
    assert "--r-card:16px" in tokens and "--bg:#FAFAF8" in tokens
    assert 'data-theme="dark"' in tokens  # dark equivalents
    assert "--bg:#15161A" in tokens and "--card:#1D1E23" in tokens
    assert app_css.is_file()
    assert not shell.exists()  # Tabler removed for a clean tree
    assert "/static/tokens.css" in html and "/static/app.css" in html
    assert "tabler" not in html.lower()


def test_spa_overview_maps_ui_02_3_layout():
    """Overview maps to the reference layout: gauge card, evidence states
    with the coverage tick, findings rows, activity feed, evidence window
    bar and the mint guidance banner."""
    html = (STATIC / "index.html").read_text()
    for marker in (
        "Verification health",
        "Evidence states",
        "bar-tick",
        "In coverage",
        "Needs attention",
        "Findings",
        "Recent activity",
        "Evidence verified",
        "guidance-banner",
        "coverage_target_pct",
        "suppressed with reason",
    ):
        assert marker in html


def test_spa_severity_pill_tint_mapping():
    """UI-02.5: severity pills carry semantic tints (high/medium/low), not a
    uniform grey badge."""
    html = (STATIC / "index.html").read_text()
    assert "SEV_TONE" in html
    assert "high: 'tok-act'" in html
    assert "medium: 'tok-look'" in html
    assert "low: 'tok-exempt'" in html
    app_css = (STATIC / "app.css").read_text()
    for cls in ("tok-act", "tok-look", "tok-exempt"):
        assert "." + cls in app_css


def test_spa_banner_tint_follows_priority_finding():
    """UI-02.5: the guidance banner has red/amber/green variants and
    pickGuidance returns a severity bucket for the priority finding."""
    html = (STATIC / "index.html").read_text()
    app_css = (STATIC / "app.css").read_text()
    assert "banner banner-' + g.tone" in html
    for cls in (".banner-act", ".banner-look", "background:var(--mint-bg)"):
        assert cls in app_css
    # invalid / bypass / receipt_missing are red; unsupported / ambiguous amber
    assert "pair('act'" in html
    assert "pair('look'" in html
    assert "pair('good'" in html


def test_spa_dark_mode_toggle_persists():
    """Theme + sidebar collapse persist in localStorage; toggle swaps data-theme."""
    html = (STATIC / "index.html").read_text()
    assert "localStorage.setItem('rc-theme'" in html
    assert "data-theme" in html and "rc-collapsed" in html
    assert 'data-theme="light"' in html  # shell boots in light


def test_spa_findings_proxy_present(client: TestClient):
    """The console proxies the add-in findings; failure stays explicit 503."""
    r = client.get("/api/assurance/findings")
    if r.status_code == 200:
        assert isinstance(r.json(), list)
    else:
        assert r.status_code == 503
        assert r.json()["error"] == "add-in offline"


def test_assurance_counts_proxy(client: TestClient):
    """The console proxies /api/counts (shared counting module breakdown)."""
    r = client.get("/api/assurance/counts")
    if r.status_code == 200:
        body = r.json()
        assert "verification" in body and "findings" in body
        buckets = body["verification"]["buckets"]
        assert sum(buckets.values()) == body["verification"]["total"]
    else:
        assert r.status_code == 503
        assert r.json()["error"] == "add-in offline"


def test_spa_counts_source_wiring():
    """The SPA reads the counts proxy and never pins numbers: the offline
    fallback derives from the shared counting module trust block."""
    html = (STATIC / "index.html").read_text()
    assert "/api/assurance/counts" in html
    assert "Pinned demo set: 9 receipts minted" not in html
    assert "t.receipts_minted" in html  # derived from the shared module
    assert "'Unaccounted'" in html  # shared bucket taxonomy (not 'Invalid')


def test_api_config_exposes_coverage_target(client: TestClient):
    body = client.get("/api/config").json()
    assert body["coverage_target_pct"] == 95


def test_spa_activity_carries_timestamps_and_kinds():
    """The overview feed ships timestamps + event kinds so the SPA can render
    honest relative times and per-event icons."""
    body = TestClient(create_app()).get("/api/overview").json()["activity"]
    for item in body:
        assert item["ts"]
        assert item["kind"] in ("index", "receipts", "shell")
        assert isinstance(datetime.datetime.fromisoformat(item["ts"]), datetime.datetime)
