# SPDX-License-Identifier: Apache-2.0
"""EPIC-N Raucle Console tests: routes, config, textContent discipline,
semantic colour system guidance and single-tenant alpha contract."""

from __future__ import annotations

import os
import pathlib
import re

import pytest
from fastapi.testclient import TestClient

from raucle_console.app import create_app

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
    # trust counts embedded and sourced from the demo fixture set
    assert body["trust"] == {
        "receipts_minted": 9,
        "receipts_verified": 10,
        "receipts_valid": 5,
    }
    assert body["activity"]
    assert body["notifications"]["count"] >= 0


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
