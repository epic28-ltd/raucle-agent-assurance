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
import json
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
RED_RUNNER_URL_DEFAULT = "http://127.0.0.1:3415"
TRUST_PORTAL_URL_DEFAULT = "http://127.0.0.1:8090"
TRUST_GATE_ENV = "RAUCLE_TRUST_GATE_CONFIG"

# Red presets the console previews to the operator. The runner remains the
# arbiter of what actually runs; these are the registered contract rows the
# console can show even before (or without) a live runner to ask.
RED_PRESETS = {
    "quick": {
        "label": "Quick pass",
        "suites": ["policy_edges", "tamper", "replay"],
        "budget": 40,
    },
    "deep": {
        "label": "Deep sweep",
        "suites": ["policy_edges", "tamper", "replay", "prompt_surface", "receipt_forgery"],
        "budget": 200,
    },
}
VALID_RED_PRESETS = tuple(RED_PRESETS)


# Embedded demo-data counts: the QA coherence pass found these pinned
# figures (9 receipts / 10 rows / 5 valid) drifting from the real fixture
# set, giving cross-surface count incoherence. They are now DERIVED at
# request time from the shared counting module - never pinned here.
def _trust_counts() -> dict:
    # Imported lazily so the module import stays cheap for tooling that
    # never serves a request; the counting module is the single source.
    from oaa_investigation_ui.counting import counts_payload  # noqa: PLC0415

    return counts_payload()


def _trend_series() -> dict:
    """BEH-01 console 'Trends': per-run bucket series over the ingested
    demo runs, derived from the SAME shared counting-module data as every
    other console figure (never pinned, never add-in-dependent - the
    windowing stays honest while the add-in is offline).

    The demo fixture set carries only individual runs, not aligned
    ingestion windows, so the series is labelled 'per run' and each point
    is one run's verification buckets over its privileged spans - the same
    loop and bucket taxonomy as counts_payload (UI-05 coherence).
    """
    from oaa_investigation_ui.counting import default_data_dir, load_cached  # noqa: PLC0415

    data = load_cached(default_data_dir())
    series = []
    for run in sorted(data.runs, key=lambda r: r["started"]):
        buckets = {"valid": 0, "unproven": 0, "unaccounted": 0}
        for trace in run["traces"]:
            for span in trace["spans"]:
                if not span.get("privileged"):
                    continue
                v = data.verification_for(span.get("receipt_hash"))
                status = v["status"]
                if status == "valid":
                    buckets["valid"] += 1
                elif status in ("invalid", "unsupported_schema"):
                    buckets["unaccounted"] += 1
                elif status not in ("unavailable", "not_applicable"):
                    buckets["unproven"] += 1
        series.append(
            {
                "label": run["run_id"],
                "at": run["started"],
                **buckets,
            }
        )
    return {
        "kind": "per run",
        "note": "one point per ingested run (demo fixture set)",
        "buckets": ("valid", "unproven", "unaccounted"),
        "points": series,
    }


# Single-tenant alpha: exactly one tenant, server-derived org identity.
TENANTS = [{"id": "default", "label": "default"}]

# Evidence-states card allowance (UI-02.3): at most this share of rows may
# sit outside coverage (unknown key etc.) before the pill flips to
# 'Needs attention'. A constant of the alpha contract, not from the env.
COVERAGE_TARGET_PCT = 95


def _red_status() -> str:
    """Red is wave 2: not purchased until the deployment opts in. Setting
    RAUCLE_RED_ENABLED=1 records the (alpha) enablement without a licence
    server - an explicit operator choice, not a default."""
    return "connected" if os.environ.get("RAUCLE_RED_ENABLED") == "1" else "not_purchased"


def _addins_catalogue() -> list:
    red = {
        "id": "red",
        "name": "Raucle Agent Red",
        "status": _red_status(),
        "wave": 2,
        "blurb": (
            "Adversarial testing for the suite: attacks your own gate and "
            "ingests its findings into Assurance."
            if _red_status() == "connected"
            else "Adversarial testing for the suite. Announcing later."
        ),
    }
    return [a for a in ADDINS if a["id"] != "red"] + [red]


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


def _red_dogfood() -> dict:
    """Raucle Agent Red dogfood telemetry: the red agent runs UNDER the gate,
    so every attack attempt leaves its own signed receipt. Counts derive from
    the red repo's corpora (local path only; absent files degrade to zeroed
    honest stubs)."""
    home = pathlib.Path(
        os.environ.get("RAUCLE_RED_HOME", "~/Projects/raucle-agent-red")
    ).expanduser()
    corpus = home / "corpora"
    out = {
        "attempts": 0,
        "receipted": 0,
        "findings_total": 0,
        "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "available": False,
    }
    attempts_file = corpus / "policy_attempts.jsonl"
    findings_file = corpus / "findings.jsonl"
    if attempts_file.exists():
        for line in attempts_file.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            out["attempts"] += 1
            if rec.get("red_receipt_present"):
                out["receipted"] += 1
            if rec.get("decision") == "allow":
                out["red_receipted_allow"] = out.get("red_receipted_allow", 0) + 1
        out["available"] = True
    if findings_file.exists():
        for line in findings_file.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            out["findings_total"] += 1
            sev = rec.get("severity", "info")
            out["findings_by_severity"][sev] = out["findings_by_severity"].get(sev, 0) + 1
    out["share"] = round(100 * out["receipted"] / out["attempts"]) if out["attempts"] else 0
    return out


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

    def _trust_portal_url() -> str:
        return os.environ.get("RAUCLE_TRUST_PORTAL_URL", TRUST_PORTAL_URL_DEFAULT)

    def _trust_gateway_url() -> str:
        """The hosted/live Trust gateway console (traffic topology, receipt
        stream, policy files, learn mode). demo.raucle.com is the public
        demo deployment; a self-hosted deployment points this at its own
        gateway UI via RAUCLE_TRUST_GATEWAY_URL."""
        return os.environ.get("RAUCLE_TRUST_GATEWAY_URL", "https://demo.raucle.com/")

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
            "addins": _addins_catalogue(),
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
    def api_config(request: fastapi.Request) -> dict:
        """Client configuration. The iframe target must be reachable FROM THE
        BROWSER, so when no explicit RAUCLE_ASSURANCE_URL override is set the
        origin is derived per request from the Host header (same host, add-in
        port) - a remote visitor embedding 127.0.0.1 would otherwise load the
        iframe from their own machine. No secrets or env dumps appear here."""
        if "RAUCLE_ASSURANCE_URL" in os.environ:
            url = _assurance_url()
        else:
            # Loopback contract: when no RAUCLE_ASSURANCE_URL override is set
            # the add-in is reached on the same host the visitor's browser is
            # already talking to, on our fixed localhost port. The scheme is
            # deliberately plain HTTP because the target is the loopback
            # add-in (ASSURANCE_URL_DEFAULT, port 3411); HTTPS would break
            # localhost without a cert. Derived from the pinned default URL
            # so the scheme itself is never re-spelled at request time.
            host = (request.headers.get("host") or "127.0.0.1").split(":", 1)[0]
            url = str(httpx.URL(ASSURANCE_URL_DEFAULT).copy_with(host=host))
        return {
            "assurance_url": url,
            "trust_portal_url": _trust_portal_url(),
            "trust_gateway_url": _trust_gateway_url(),
            "addins": _addins_catalogue(),
            "assurance_reachable": False,  # SPA probes the URL itself
            "trust_gate_env": TRUST_GATE_ENV,
            "coverage_target_pct": COVERAGE_TARGET_PCT,
        }

    @app.get("/api/trust/policies/summary")
    def api_trust_policies_summary() -> JSONResponse:
        """Same-origin proxy for the H1 portal's /api/v1/policies/summary
        (Trust-dashboard reconcile decision, 4 Nov: the portal owns deep
        policy management; the console narrates and links, never edits).
        The portal's summary endpoint is authenticated and the console
        holds no portal credential in alpha, so a 401/403 from the portal
        is passed through as the honest pending state - never guessed,
        never faked. Same graceful degradation contract as the other
        add-in proxies."""
        try:
            r = httpx.get(
                _trust_portal_url().rstrip("/") + "/api/v1/policies/summary",
                timeout=3.0,
            )
            if r.status_code == 200:
                return JSONResponse(r.json())
            return JSONResponse(
                {"error": "portal summary unavailable", "status": r.status_code},
                status_code=r.status_code,
            )
        except Exception as exc:  # offline: explicit, never a blank
            return JSONResponse(
                {"error": "portal offline", "detail": type(exc).__name__},
                status_code=503,
            )

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

    @app.get("/api/trends")
    def api_trends() -> dict:
        """Per-run bucket series for the Overview Trends card. Derived from
        the shared counting module's demo fixture set (same source as every
        console figure); the add-in's live runs replace these when the
        proxy contract is extended with windows."""
        return _trend_series()

    @app.get("/api/red/dogfood")
    def api_red_dogfood() -> dict:
        """The red agent's own gate receipts (dogfooding, EPIC L invariant 1)."""
        return _red_dogfood()

    def _red_runner_url() -> str:
        return os.environ.get("RAUCLE_RED_RUNNER_URL", RED_RUNNER_URL_DEFAULT)

    def _proxy_red(method: str, path: str, *, body=None):
        """Forward a call to the red runner with explicit offline handling:
        an unreachable runner degrades to a 503 the SPA renders honestly -
        never a blank card, never a guessed status. Runner-side validation
        errors (e.g. unknown preset) pass their own status through."""
        try:
            r = httpx.request(
                method,
                _red_runner_url().rstrip("/") + path,
                json=body,
                timeout=5.0,
            )
            r.raise_for_status()
            return JSONResponse(r.json())
        except httpx.HTTPStatusError as exc:
            try:
                detail = exc.response.json()
            except ValueError:
                detail = {"error": "runner error", "detail": exc.response.text[:300]}
            return JSONResponse(detail, status_code=exc.response.status_code)
        except Exception as exc:  # connection refused, timeout, DNS: offline
            return JSONResponse(
                {"error": "red runner offline", "detail": type(exc).__name__},
                status_code=503,
            )

    @app.get("/api/red/targets")
    def api_red_targets() -> JSONResponse:
        """Proxy the runner's /targets: the demo gateway plus any named gates
        registered with it (with endpoint / policy digest per gate)."""
        return _proxy_red("GET", "/targets")

    @app.post("/api/red/run")
    async def api_red_run(request: fastapi.Request) -> JSONResponse:
        """Proxy the runner's POST /run. The requested preset is checked at
        the console as well (cheap misuse filter); the runner remains the
        arbiter and any runner-side rejection is passed through verbatim."""
        try:
            body = await request.json()
        except ValueError:
            body = {}
        preset = body.get("preset") if isinstance(body, dict) else None
        target = body.get("target") if isinstance(body, dict) else None
        if preset not in VALID_RED_PRESETS:
            return JSONResponse(
                {"error": "preset must be one of: " + ", ".join(VALID_RED_PRESETS)},
                status_code=422,
            )
        if not isinstance(target, str) or not target:
            return JSONResponse({"error": "target must be a non-empty string"}, status_code=422)
        return _proxy_red("POST", "/run", body={"preset": preset, "target": target})

    @app.get("/api/red/status")
    def api_red_status() -> JSONResponse:
        """Proxy the runner's /status for the live results poll."""
        return _proxy_red("GET", "/status")

    @app.get("/api/red/results")
    def api_red_results() -> JSONResponse:
        """Proxy the runner's /results (finding rows + receipts counter)."""
        return _proxy_red("GET", "/results")

    @app.post("/api/red/stop")
    def api_red_stop() -> JSONResponse:
        """Proxy the runner's POST /stop (aborts a run in flight)."""
        return _proxy_red("POST", "/stop")

    @app.get("/api/assurance/findings/red")
    def api_assurance_findings_red() -> JSONResponse:
        """Server-side GET proxy for the add-in's ingested-red-finding slice.

        The SPA must not fetch the add-in cross-origin (the add-in sends no
        CORS headers by design), so every read the Red page needs goes through
        this same-origin proxy with the same explicit degradation."""
        try:
            r = httpx.get(
                _assurance_url().rstrip("/") + "/api/findings/red",
                timeout=5.0,
            )
            return JSONResponse(r.json(), status_code=r.status_code)
        except Exception as exc:  # explicit degradation, never a blank
            return JSONResponse(
                {"error": "add-in offline", "detail": type(exc).__name__},
                status_code=503,
            )

    @app.post("/api/assurance/findings/ingest")
    async def api_assurance_findings_ingest(request: fastapi.Request) -> JSONResponse:
        """Server-side proxy for the add-in's findings intake (the same
        graceful degradation contract as the GET proxies above). The add-in
        validates the red schema itself; a 422 passes through so the SPA can
        show exactly what was rejected. Ingestion is idempotent by
        finding_id, so a re-post of the same run is a no-op."""
        body = await request.body()
        try:
            r = httpx.post(
                _assurance_url().rstrip("/") + "/api/findings/ingest",
                content=body,
                headers={"content-type": "application/json"},
                timeout=5.0,
            )
            r.raise_for_status()
            return JSONResponse(r.json())
        except httpx.HTTPStatusError as exc:
            try:
                detail = exc.response.json()
            except ValueError:
                detail = {"error": exc.response.text[:300]}
            return JSONResponse(detail, status_code=exc.response.status_code)
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
