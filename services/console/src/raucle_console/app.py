# SPDX-License-Identifier: Apache-2.0
"""Raucle Console - EPIC-N application shell (FastAPI).

The console is the ONE application shell for the Raucle agent suite;
suite products are ADD-INS purchased separately:

- Raucle Agent Trust   - gate / evidence core (counts embedded from the
  pinned demo fixture set);
- Raucle Agent Assurance - investigation add-in (EXISTS; embedded as an
  iframe to a configurable URL, default http://127.0.0.1:3411);
- Raucle Agent Red     - wave 2, not started (coming soon).

Server contract: org identity is server-derived per the ADR contract; the
console is a single-tenant alpha with one tenant ('default') and no cookie
/ session handling - authenticated multi-tenancy is a later epic.

UX hard rules (threat model T5, shared with investigation-ui):
- the SPA renders with textContent only - no innerHTML anywhere;
- no external fetches from the page (the only outbound call the SPA makes
  is the configured add-in origin shown to the operator);
- semantic colour system: green = proven, amber = un-proven, red = action
  needed, grey = exempt / not purchased; a legend is always present.
"""

from __future__ import annotations

import datetime
import os
import pathlib
import sys

import fastapi
import httpx
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

_static_dir = pathlib.Path(__file__).resolve().parents[2] / "static"

# Shared counting module (UI-05 coherence pass): the console NEVER computes
# its own numbers - its trust figures and offline fallbacks are the output
# of the same count_evidence() the investigation UI serves on /api/counts,
# imported across services from the same pinned demo fixture set.
_repo_root = pathlib.Path(__file__).resolve().parents[4]
_investigation_src = _repo_root / "services" / "investigation-ui" / "src"
if _investigation_src.is_dir() and str(_investigation_src) not in sys.path:
    sys.path.insert(0, str(_investigation_src))

# Add-in origins come from the environment at start-up; nothing is hardcoded
# beyond the documented defaults. Env values are never echoed verbatim - only
# the URL the console was told to use for an add-in, which the operator set.
ASSURANCE_URL_DEFAULT = "http://127.0.0.1:3411"
TRUST_GATE_ENV = "RAUCLE_TRUST_GATE_CONFIG"


# Embedded demo-data counts: the QA coherence pass found these pinned
# figures (9 receipts / 10 rows / 5 valid) drifting from the real fixture
# set, giving cross-surface count incoherence. They are now DERIVED at
# request time from the shared counting module - never pinned here.
def _trust_counts() -> dict:
    # Imported lazily so the module import stays cheap for tooling that
    # never serves a request; the counting module is the single source.
    from oaa_investigation_ui.counting import counts_payload  # noqa: PLC0415

    return counts_payload()


# Single-tenant alpha: exactly one tenant, server-derived org identity.
TENANTS = [{"id": "default", "label": "default"}]

# Evidence-states card allowance (UI-02.3): at most this share of rows may
# sit outside coverage (unknown key etc.) before the pill flips to
# 'Needs attention'. A constant of the alpha contract, not from the env.
COVERAGE_TARGET_PCT = 95

# Add-in catalogue: status drives the semantic chip colour.
ADDINS = [
    {
        "id": "trust",
        "name": "Raucle Agent Trust",
        "status": "connected",
        "wave": 1,
        "blurb": "Gate and evidence core: receipts, verification "
        "and policy decisions for agent tool calls.",
    },
    {
        "id": "assurance",
        "name": "Raucle Agent Assurance",
        "status": "connected",
        "wave": 1,
        "blurb": "Investigate tool calls end to end: traces, evidence "
        "receipts, findings and correlation.",
    },
    {
        "id": "red",
        "name": "Raucle Agent Red",
        "status": "not_purchased",
        "wave": 2,
        "blurb": "Adversarial testing for the suite. Announcing later.",
    },
]

# Activity feed timestamps: recorded at module start (the console's own boot
# moment plus fixture offsets), in UTC ISO-8601. The SPA derives honest
# relative labels ("4m ago") from these; the server never fakes a trend.
_now = datetime.datetime.now(datetime.UTC)


def _ago(seconds: float) -> str:
    return (_now - datetime.timedelta(seconds=seconds)).isoformat()


ACTIVITY_PLACEHOLDER = [
    {
        "ts": _ago(4 * 60),
        "kind": "index",
        "what": "Assurance add-in investigation data: 2 demo runs indexed",
    },
    {
        "ts": _ago(37 * 60),
        "kind": "receipts",
        "what": "Trust add-in: receipts minted in the pinned demo set",
    },
    {
        "ts": _ago(26 * 3600),
        "kind": "shell",
        "what": "Console shell started - no tenant activity reported yet",
    },
]


def create_app() -> fastapi.FastAPI:
    app = fastapi.FastAPI(title="Raucle Console (EPIC-N)", version="0.1.0")

    def _assurance_url() -> str:
        return os.environ.get("RAUCLE_ASSURANCE_URL", ASSURANCE_URL_DEFAULT)

    # ------------------------------------------------------------ API (JSON)
    @app.get("/api/overview")
    def api_overview() -> dict:
        """Suite summary: add-in catalogue, shared-module Trust counts, activity.

        Assurance counters are fetched by the SPA from the add-in itself
        (graceful 'add-in offline' empty state) so the console stays static.
        Notification counts are computed here - never echoed from env.
        """
        counts = _trust_counts()
        trust = counts["trust"]
        trust_view = {
            "receipts_minted": trust["receipts_minted"],
            "receipts_verified": trust["verification_rows"],
            "receipts_valid": trust["verification_valid"],
            # index-plane fallback figures (same module, same demo data):
            # the SPA uses these only when the add-in is offline, so the
            # numbers agree with the add-in's own /api/counts either way.
            "spans_indexed": counts["verification"]["total"],
            "verification_distribution": counts["verification"]["states"],
            "verification_buckets": counts["verification"]["buckets"],
            "correlation_distribution": counts["correlation"]["states"],
            "findings": counts["findings"],
            "source": "shared counting module over the pinned demo fixture set",
        }
        activity = [item for item in ACTIVITY_PLACEHOLDER if item["kind"] != "receipts"]
        activity.insert(
            0,
            {
                "ts": ACTIVITY_PLACEHOLDER[1]["ts"],
                "kind": "receipts",
                "what": f"Trust add-in: {trust['receipts_minted']} receipts minted "
                f"and {trust['verification_rows']} verification rows "
                f"({trust['verification_valid']} valid) in the pinned demo set",
            },
        )
        return {
            "tenants": TENANTS,
            "addins": ADDINS,
            "trust": trust_view,
            "activity": activity,
            "notifications": {
                "count": 2,
                "items": [
                    f"Trust add-in: {trust['receipts_minted']} receipts minted "
                    f"in the pinned demo set",
                    "Assurance add-in: connect the live investigation process",
                ],
            },
            "single_tenant_alpha": True,
        }

    @app.get("/api/config")
    def api_config() -> dict:
        """Client configuration. The iframe target is the configured add-in
        origin only; no secrets or environment dumps appear here. The
        coverage allowance (UI-02.3) is a constant of the alpha contract."""
        return {
            "assurance_url": _assurance_url(),
            "assurance_reachable": False,  # SPA probes the URL itself
            "trust_gate_env": TRUST_GATE_ENV,
            "coverage_target_pct": COVERAGE_TARGET_PCT,
        }

    @app.get("/api/assurance/dashboard")
    def api_assurance_dashboard() -> JSONResponse:
        """Server-side proxy for the add-in's own /api/dashboard.

        The SPA cannot fetch the add-in cross-origin (the add-in sends no
        CORS headers, by design for alpha), so the console proxies. A failure
        surfaces explicitly so the SPA can show its 'add-in offline' state.
        """
        try:
            r = httpx.get(_assurance_url().rstrip("/") + "/api/dashboard", timeout=3.0)
            r.raise_for_status()
            return JSONResponse(r.json())
        except Exception as exc:  # explicit degradation, never a blank
            return JSONResponse(
                {"error": "add-in offline", "detail": type(exc).__name__},
                status_code=503,
            )

    @app.get("/api/assurance/counts")
    def api_assurance_counts() -> JSONResponse:
        """Server-side proxy for the add-in's own /api/counts (UI-05
        coherence pass: the full shared counting-module breakdown). Same
        graceful degradation contract as the dashboard proxy."""
        try:
            r = httpx.get(_assurance_url().rstrip("/") + "/api/counts", timeout=3.0)
            r.raise_for_status()
            return JSONResponse(r.json())
        except Exception as exc:  # explicit degradation, never a blank
            return JSONResponse(
                {"error": "add-in offline", "detail": type(exc).__name__},
                status_code=503,
            )

    @app.get("/api/assurance/findings")
    def api_assurance_findings() -> JSONResponse:
        """Server-side proxy for the add-in's /api/findings (UI-02.3: the
        overview findings card needs rule_id / severity / suppression for
        rows, which the dashboard aggregate does not carry). Same graceful
        degradation contract as the dashboard proxy."""
        try:
            r = httpx.get(_assurance_url().rstrip("/") + "/api/findings", timeout=3.0)
            r.raise_for_status()
            return JSONResponse(r.json())
        except Exception as exc:  # explicit degradation, never a blank
            return JSONResponse(
                {"error": "add-in offline", "detail": type(exc).__name__},
                status_code=503,
            )

    @app.get("/api/health")
    def api_health() -> dict:
        return {"service": "raucle-console", "status": "ok"}

    # ------------------------------------------------------------ static SPA
    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(_static_dir / "index.html")

    @app.get("/static/index.html", include_in_schema=False)
    def spa() -> FileResponse:
        return FileResponse(_static_dir / "index.html")

    # Vendored UI assets (Inter font) and the token/app stylesheets are all
    # served locally only: the SPA never fetches anything external at
    # runtime (threat-model T5). The Tabler CSS vendor tree was removed with
    # the UI-02.3 quiet-SaaS rebuild; the shell styles itself entirely from
    # static/tokens.css + static/app.css.
    app.mount(
        "/static",
        StaticFiles(directory=_static_dir),
        name="static",
    )

    return app


app = create_app()
