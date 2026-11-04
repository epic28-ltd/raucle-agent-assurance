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

import os
import pathlib

import fastapi
import httpx
from fastapi.responses import FileResponse, JSONResponse

_static_dir = pathlib.Path(__file__).resolve().parents[2] / "static"

# Add-in origins come from the environment at start-up; nothing is hardcoded
# beyond the documented defaults. Env values are never echoed verbatim - only
# the URL the console was told to use for an add-in, which the operator set.
ASSURANCE_URL_DEFAULT = "http://127.0.0.1:3411"
TRUST_GATE_ENV = "RAUCLE_TRUST_GATE_CONFIG"

# Embedded demo-data counts (pinned investigation-ui demo_data fixture set:
# synthetic_receipt_index.jsonl = 9 receipts; verification_index.jsonl = 10
# rows, 5 of them valid). Sourced, not invented - refresh with the fixture.
TRUST_OVERVIEW = {
    "receipts_minted": 9,
    "receipts_verified": 10,
    "receipts_valid": 5,
}

# Single-tenant alpha: exactly one tenant, server-derived org identity.
TENANTS = [{"id": "default", "label": "default"}]

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

ACTIVITY_PLACEHOLDER = [
    {"when": "demo fixture", "what": "Assurance add-in investigation data: 2 demo runs indexed"},
    {"when": "demo fixture", "what": "Trust add-in: 9 receipts minted in the pinned demo set"},
    {"when": "alpha", "what": "Console shell started - no tenant activity recorded yet"},
]


def create_app() -> fastapi.FastAPI:
    app = fastapi.FastAPI(title="Raucle Console (EPIC-N)", version="0.1.0")

    def _assurance_url() -> str:
        return os.environ.get("RAUCLE_ASSURANCE_URL", ASSURANCE_URL_DEFAULT)

    # ------------------------------------------------------------ API (JSON)
    @app.get("/api/overview")
    def api_overview() -> dict:
        """Suite summary: add-in catalogue, embedded Trust counts, activity.

        Assurance counters are fetched by the SPA from the add-in itself
        (graceful 'add-in offline' empty state) so the console stays static.
        Notification counts are computed here - never echoed from env.
        """
        return {
            "tenants": TENANTS,
            "addins": ADDINS,
            "trust": TRUST_OVERVIEW,
            "activity": ACTIVITY_PLACEHOLDER,
            "notifications": {
                "count": 2,
                "items": [
                    "Trust add-in: 9 receipts minted in the pinned demo set",
                    "Assurance add-in: connect the live investigation process",
                ],
            },
            "single_tenant_alpha": True,
        }

    @app.get("/api/config")
    def api_config() -> dict:
        """Client configuration. The iframe target is the configured add-in
        origin only; no secrets or environment dumps appear here."""
        return {
            "assurance_url": _assurance_url(),
            "assurance_reachable": False,  # SPA probes the URL itself
            "trust_gate_env": TRUST_GATE_ENV,
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

    return app


app = create_app()
