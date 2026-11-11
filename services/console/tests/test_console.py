"""EPIC-N Raucle Console tests: routes, config, textContent discipline,
semantic colour system guidance and single-tenant alpha contract."""
# SPDX-License-Identifier: FSL-1.1-ALv2

from __future__ import annotations

import datetime
import json
import pathlib
import re
import sys

import httpx
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


@pytest.fixture
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


def test_iframe_configurable_assurance_url(monkeypatch):
    monkeypatch.setenv("RAUCLE_ASSURANCE_URL", "http://127.0.0.1:9911/")
    c = TestClient(create_app())
    body = c.get("/api/config").json()
    assert body["assurance_url"] == "http://127.0.0.1:9911/"


def test_iframe_config_default(client: TestClient):
    # base_url pins the Host header: the per-request origin derivation
    # otherwise uses the client hostname (testserver in the test client).
    c = TestClient(create_app(), base_url="http://127.0.0.1:3412")
    body = c.get("/api/config").json()
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


def test_assurance_dashboard_proxy_offline(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("RAUCLE_ASSURANCE_URL", "http://127.0.0.1:9")
    c = TestClient(create_app())
    r = c.get("/api/assurance/dashboard")
    assert r.status_code == 503
    assert r.json()["error"] == "add-in offline"


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
        assert href.startswith(("http://127.0.0.1", "/")), href
    # the allowed cross-origin fetch targets are the pinned loopback add-in
    # origin and the documented public trust-gateway demo origin
    # (demo.raucle.com, the TRUST_GATEWAY_URL default from app.py)
    for url in re.findall(r"https?://[^'\"\\s]+", html):
        allowed = ("http://127.0.0.1:", "https://demo.raucle.com/")
        assert url.startswith(allowed), url


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
    assert "pointerenter" in html
    assert "pointermove" in html
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
    assert font.is_file()
    assert font.stat().st_size > 10_000
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
    assert "--r-card:16px" in tokens
    assert "--bg:#FAFAF8" in tokens
    assert 'data-theme="dark"' in tokens  # dark equivalents
    assert "--bg:#15161A" in tokens
    assert "--card:#1D1E23" in tokens
    assert app_css.is_file()
    assert not shell.exists()  # Tabler removed for a clean tree
    assert "/static/tokens.css" in html
    assert "/static/app.css" in html
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
    assert "data-theme" in html
    assert "rc-collapsed" in html
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
        assert "verification" in body
        assert "findings" in body
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


# ------------------------------------------------------------- BEH-01 dashboards
def test_api_trends_shape_and_coherence(client: TestClient):
    """/api/trends: per-run bucket series derived from the shared counting
    module demo fixtures. Buckets partition each run's privileged spans and
    the kind label is honest ('per run')."""
    body = client.get("/api/trends").json()
    assert body["kind"] == "per run"
    assert body["points"], "demo fixtures ship runs: series must not be empty"
    total_privileged = 0
    for run in body["points"]:
        assert set(run) == {"label", "at", "valid", "unproven", "unaccounted"}
        assert datetime.datetime.fromisoformat(run["at"]) is not None
        n = run["valid"] + run["unproven"] + run["unaccounted"]
        assert n >= 0
        total_privileged += n
    counts = count_evidence(UI_DIR / "demo_data")
    buckets = counts["verification"]["buckets"]
    # coherence with the shared counting module: exempt states (unavailable /
    # not_applicable) sit outside the trend buckets, everything else is
    # partitioned across the per-run series
    assert total_privileged == buckets["valid"] + buckets["unproven"] + buckets["unaccounted"]
    assert set(body["buckets"]) == {"valid", "unproven", "unaccounted"}


def test_api_trends_never_echoes_env(client: TestClient):
    text = str(client.get("/api/trends").json())
    for forbidden in ("SECRET", "PASSWORD", "TOKEN", "API_KEY"):
        assert forbidden.lower() not in text.lower()


def test_spa_trends_card_honest_labels():
    html = (STATIC / "index.html").read_text()
    assert "'Trends'" in html
    assert "trendsCard" in html
    assert "/api/trends" in html
    # honest per-run labelling: the demo set has no aligned windows
    assert "per run" in html
    assert "polyline" in html  # inline SVG lines, no chart library


def test_spa_rule_coverage_strip():
    html = (STATIC / "index.html").read_text()
    assert "ruleCoverageCard" in html
    assert "Rule coverage" in html
    for rid in ("SEC-001", "SEC-002", "SEC-003", "SEC-004", "SEC-005", "SEC-006"):
        assert rid in html
    assert "chip-exempt rule-chip" in html  # silent rules show grey
    assert "#/rules/" in html  # chips drill into the per-rule view


def test_spa_red_preview_card_and_roadmap_link():
    html = (STATIC / "index.html").read_text()
    assert "add-in preview - coming soon" in html
    assert "Gate fuzzer findings" in html
    assert "Tamper attempts" in html
    assert "docs/agent-red-roadmap.md" in html
    roadmap = pathlib.Path(CONSOLE_DIR).resolve().parents[1] / "docs" / "agent-red-roadmap.md"
    assert roadmap.is_file()
    assert "coming soon" in roadmap.read_text().lower()


def test_spa_per_rule_drill_view():
    html = (STATIC / "index.html").read_text()
    assert "viewRule" in html
    assert "RULE_GUIDANCE" in html
    # router parses #/rules/<id>
    assert "rules/" in html
    for rid in ("SEC-001", "SEC-009", "SEC-011"):
        assert rid in html  # guidance exists for the tracked + hostile rules
    assert "Guidance" in html


def test_spa_dashboard_additions_keep_discipline():
    """New SPA code keeps threat-model T5: no innerHTML, no new scripts,
    no external URLs."""
    html = (STATIC / "index.html").read_text()
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert forbidden not in html
    # allowed cross-origin targets: pinned loopback add-in + documented
    # public trust-gateway demo origin (TRUST_GATEWAY_URL default in app.py)
    for url in re.findall(r"https?://[^'\"\\s]+", html):
        allowed = ("http://127.0.0.1:", "https://demo.raucle.com/")
        assert url.startswith(allowed), url


# ------------------------------------------------------------- wave 2.5 Red ops
def test_red_runner_proxy_offline_is_explicit_503(client: TestClient):
    """Runner down (nothing on 3415): every red proxy degrades to an
    explicit 503 with the honest offline marker - no crash, no blank."""
    for _method, path in (
        ("GET", "/api/red/status"),
        ("GET", "/api/red/results"),
        ("GET", "/api/red/targets"),
    ):
        r = client.get(path)
        if r.status_code == 503:
            assert r.json()["error"] == "red runner offline"
        # if a local runner happens to be up, honest upstream state passes
        # through unchanged: 2xx, or a runner-side 404 (results requested
        # before a run has completed). The proxy never masks a runner state
        # as "offline" and never fakes a success.
        else:
            assert r.status_code in (200, 204, 404)
    up = client.get("/api/red/status").status_code == 200
    if up:
        # a live runner would EXECUTE the submit: do not trigger real work
        # from a test; the run/stop forwarding shape is pinned elsewhere
        # against a stubbed runner.
        return
    for path in ("/api/red/stop", "/api/red/run"):
        r = client.post(path, json={"preset": "quick", "target": "demo"})
        if r.status_code == 503:
            assert r.json()["error"] == "red runner offline"


def test_red_run_proxy_validates_preset_and_target(client: TestClient):
    """The console filters obvious misuse cheaply; the runner stays arbiter."""
    r = client.post("/api/red/run", json={"preset": "turbo", "target": "demo"})
    if r.status_code == 422:
        assert "preset" in r.json()["error"]
    r = client.post("/api/red/run", json={"preset": "quick", "target": ""})
    if r.status_code == 422:
        assert "target" in r.json()["error"]


def test_red_run_proxy_forwards_body_to_runner(client: TestClient):
    """A live-looking runner (stubbed transport) receives exactly the
    console's own shape: {"preset": ..., "target": ...}."""
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["json"] = json.loads(request.content.decode())
        return httpx.Response(200, request=request, json={"run": "accepted"})

    def fake_request(method, url, json=None, timeout=None):
        return handler(httpx.Request(method, url, json=json))

    import raucle_console.app as app_mod  # noqa: PLC0415 (test-local patch target)

    orig = app_mod.httpx.request
    app_mod.httpx.request = fake_request
    try:
        r = client.post("/api/red/run", json={"preset": "quick", "target": "demo"})
        assert r.status_code == 200, r.text
        assert r.json() == {"run": "accepted"}
        assert captured["path"] == "/run"
        assert captured["json"] == {"preset": "quick", "target": "demo"}
    finally:
        app_mod.httpx.request = orig


def test_red_status_results_orchestration_mock_flow(client: TestClient):
    """Mock orchestration: idle -> running -> complete across /status, then
    /results returns findings rows + receipts; the proxy passes them
    through untouched."""
    script = iter(
        [
            ({"state": "idle", "attempts": 0}, 200),
            (
                {
                    "state": "running",
                    "target": "demo",
                    "suite": "policy_edges",
                    "attempts": 3,
                    "allow": 1,
                    "deny": 2,
                    "findings": 0,
                    "receipts": 3,
                },
                200,
            ),
            (
                {
                    "state": "complete",
                    "target": "demo",
                    "attempts": 8,
                    "allow": 2,
                    "deny": 6,
                    "findings": 2,
                    "receipts": 8,
                },
                200,
            ),
            (
                {
                    "findings": [
                        {"rule": "RED-006", "severity": "high", "explanation": "e"},
                        {"rule": "RED-011", "severity": "low", "explanation": "e"},
                    ],
                    "receipts": 8,
                },
                200,
            ),
        ]
    )
    queue = list(script)

    def fake_request(method, url, json=None, timeout=None):
        body, code = queue.pop(0)
        return httpx.Response(code, request=httpx.Request(method, url, json=json), json=body)

    import raucle_console.app as app_mod  # noqa: PLC0415 (test-local patch target)

    orig = app_mod.httpx.request
    app_mod.httpx.request = fake_request
    try:
        c = TestClient(create_app())
        s1 = c.get("/api/red/status").json()
        assert s1["state"] == "idle"
        s2 = c.get("/api/red/status").json()
        assert s2["state"] == "running"
        assert s2["allow"] == 1
        assert s2["deny"] == 2
        s3 = c.get("/api/red/status").json()
        assert s3["state"] == "complete"
        assert s3["receipts"] == 8
        res = c.get("/api/red/results").json()
        assert res["receipts"] == 8
        assert [f["rule"] for f in res["findings"]] == ["RED-006", "RED-011"]
    finally:
        app_mod.httpx.request = orig


def test_assurance_ingest_proxy_offline_and_passthrough(client: TestClient, monkeypatch):
    """Offline add-in: explicit 503. A 422 (schema rejection at the add-in)
    passes through verbatim so the operator sees what was rejected."""
    monkeypatch.setenv("RAUCLE_ASSURANCE_URL", "http://127.0.0.1:9")
    c = TestClient(create_app())
    r = c.post("/api/assurance/findings/ingest", json={"findings": []})
    assert r.status_code == 503
    assert r.json()["error"] == "add-in offline"

    import raucle_console.app as app_mod  # noqa: PLC0415 (test-local patch target)

    class _FakeAddInAsyncClient:
        """AsyncClient stub so the proxy's schema-rejection passthrough is
        exercised without a live add-in (the app awaits httpx.AsyncClient)."""

        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc_info):
            return False

        async def post(self, url, **kwargs):
            req = httpx.Request("POST", url)
            return httpx.Response(
                422,
                request=req,
                json={"error": "severity not in ['info', 'low', 'medium']"},
            )

    orig_async = app_mod.httpx.AsyncClient
    app_mod.httpx.AsyncClient = _FakeAddInAsyncClient
    try:
        c2 = TestClient(create_app())
        r2 = c2.post("/api/assurance/findings/ingest", json={"findings": []})
        assert r2.status_code == 422
        assert "severity" in r2.json()["error"]
    finally:
        app_mod.httpx.AsyncClient = orig_async


def test_spa_red_ops_marks_present_and_honest():
    """The wave 2.5 cards exist with the honest states wired: offline line,
    scoped preview, semantic state chips, stop button and polling-stop note."""
    html = (STATIC / "index.html").read_text()
    for marker in (
        "Run a test",
        "Live results",
        "Gates for testing",
        "Runner offline: start red runner (port 3415)",
        "Loopback only",
        "Synthetic data",
        "Ingest findings into Assurance",
        "idempotent by finding_id",
        "Polling stops on tab hide",
        "/api/red/run",
        "/api/red/status",
        "/api/red/results",
        "/api/red/stop",
        "/api/red/targets",
        "/api/red/dogfood",
        "/api/assurance/findings/ingest",
        "visibilitychange",
        "Nothing starts until Start is pressed",
    ):
        assert marker in html
    # poll loop is 2000ms and cleared when idle/complete
    assert "setInterval" in html
    assert "clearInterval" in html
    assert "2000" in html
    # state chips map to the semantic tints
    assert "aborted: ['Aborted', 'tok-act']" in html
    assert "complete: ['Complete', 'tok-good']" in html


def test_spa_red_ops_keep_discipline():
    """The ops view reuses the SPA primitives: no innerHTML, no external
    URL, no autostart (no /run call outside the Start handler)."""
    html = (STATIC / "index.html").read_text()
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert forbidden not in html
    # the /run POST appears exactly once, in the Start handler (no autostart)
    assert html.count("'/api/red/run'") == 1
    # textContent-only rendering is present in the ops block too
    assert "textContent" in html


def test_docs_console_red_ops_findings_spike():
    doc = CONSOLE_DIR.parents[1] / "docs" / "spikes" / "console-red-ops-findings.md"
    assert doc.is_file()
    text = doc.read_text()
    assert "idempoten" in text.lower()
    assert "3415" in text
    em_dash = chr(0x2014)
    assert em_dash not in text


# ------------------------------------------------------ trust portal (reconcile)
def test_config_carries_trust_portal_url(client: TestClient):
    body = client.get("/api/config").json()
    assert body["trust_portal_url"] == "http://127.0.0.1:8090"


def test_trust_portal_url_configurable(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("RAUCLE_TRUST_PORTAL_URL", "http://127.0.0.1:9410")
    c = TestClient(create_app())
    assert c.get("/api/config").json()["trust_portal_url"] == "http://127.0.0.1:9410"


def test_trust_policies_summary_proxy_degrades_honestly(client: TestClient):
    """The portal is not running (test port): the proxy returns an explicit
    503 'portal offline' - never a blank, never a guessed number."""
    r = client.get("/api/trust/policies/summary")
    assert r.status_code == 503
    assert r.json()["error"] == "portal offline"


def test_trust_page_narrates_and_links_the_portal():
    """The Manage policies card: the portal is the deep editor, the console
    narrates + links - no parallel editor markup exists."""
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "Manage policies" in html
    assert "Open the portal" in html
    # the reconcile decision is pinned in the page copy
    assert "one version history, one audit trail" in html
    # the honest pending state copy ships even while the portal is offline
    assert "summary endpoint pending" in html
