# SPDX-License-Identifier: Apache-2.0
"""Open Agent Assurance — UI-01 investigation UI (FastAPI).

Views per the story 'Investigate tool calls':

- runs list: run_id, agent, release, span count, verification summary,
  correlation state per privileged tool call;
- trace drilldown: span tree with, per privileged span, its evidence
  reference (receipt_hash), verification status rendered from the full
  ADR-0001 state enum and correlation state (ADR-0002) — explicit unknown
  states are styled distinctly and are NEVER silently blank;
- evidence panel: metadata only (receipt_hash, schema_version, gate
  decision, policy_ref) + 'Verify offline' button running evidence-plane
  ``classify`` over the canonical bytes; the raw JWS is shown as
  "available for download" only;
- findings panel: rule_id, severity, confidence, suppressed findings
  retained with suppression_reason (RULE-01).

UX hard rules (threat model T5):
- all model/tool content renders as hostile text (server-rendered views
  escape with html.escape; the SPA renders with textContent — no innerHTML);
- no auto-link resolution, no external fetches from the page, no secret
  display (JWS bodies, trust keys, env values never appear in output).
"""

from __future__ import annotations

import html
import json
import os
import pathlib

import fastapi
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from .data import DemoData, default_data_dir
from .verify import verify_offline

DATA_DIR = default_data_dir()
_static_dir = pathlib.Path(__file__).resolve().parents[2] / "static"


def esc(value) -> str:
    """Hostile-text rendering: escape EVERYTHING; no link resolution."""
    return html.escape(str(value), quote=True)


def create_app(data_dir: pathlib.Path | None = None) -> fastapi.FastAPI:
    app = fastapi.FastAPI(title="OAA Investigation UI (UI-01)", version="0.1.0")
    data = DemoData(data_dir or DATA_DIR)

    def _run_summary(run: dict) -> dict:
        verif: dict[str, int] = {}
        corr: dict[str, int] = {}
        span_count = 0
        privileged = 0
        for trace in run["traces"]:
            for span in trace["spans"]:
                span_count += 1
                if span.get("privileged"):
                    privileged += 1
                    status = data.verification_for(span.get("receipt_hash"))
                    verif[status["status"]] = verif.get(status["status"], 0) + 1
                    c = data.correlation_for_span(span, trace["trace_id"])
                    corr[c["state"]] = corr.get(c["state"], 0) + 1
        return {
            "span_count": span_count,
            "privileged_span_count": privileged,
            "verification_summary": verif,
            "correlation_summary": corr,
            "pending_correlation": data.pending_count,
        }

    def _run_findings(run: dict) -> list[dict]:
        traces = {t["trace_id"] for t in run["traces"]}
        hashes = {s["receipt_hash"] for t in run["traces"] for s in t["spans"] if s["receipt_hash"]}
        out = []
        for f in data.findings:
            refs = set(f["evidence_refs"])
            if refs & traces or refs & hashes:
                out.append(f)
        return out

    # ------------------------------------------------------------ API (JSON)
    @app.get("/api/runs")
    def api_runs():
        return [
            {
                **{k: r[k] for k in ("run_id", "agent", "release", "started")},
                **_run_summary(r),
            }
            for r in data.runs
        ]

    @app.get("/api/runs/{run_id}")
    def api_run(run_id: str):
        run = data.get_run(run_id)
        if run is None:
            return JSONResponse({"error": "unknown run_id"}, status_code=404)
        traces = []
        for trace in run["traces"]:
            spans = []
            for span in trace["spans"]:
                spans.append(
                    {
                        "span_id": span["span_id"],
                        "parent_id": span["parent_id"],
                        "name": span["name"],
                        "tool": span["tool"],
                        "privileged": span["privileged"],
                        "started": span["started"],
                        "attrs": span["attrs"],  # hostile content: SPA renders via textContent
                        "receipt_hash": span["receipt_hash"],
                        "verification": data.verification_for(span.get("receipt_hash")),
                        "correlation": data.correlation_for_span(span, trace["trace_id"]),
                        "evidence_canonical": bool(
                            data.store_line(span.get("receipt_hash") or "")
                            if span["receipt_hash"]
                            else False
                        ),
                    }
                )
            corr = data.correlation_by_trace.get(trace["trace_id"])
            traces.append(
                {
                    "trace_id": trace["trace_id"],
                    "label": trace["label"],
                    "window_start": trace["window_start"],
                    "window_end": trace["window_end"],
                    "correlation": corr,
                    "spans": spans,
                }
            )
        return {
            **{k: run[k] for k in ("run_id", "agent", "release", "started")},
            **_run_summary(run),
            "traces": traces,
            "findings": _run_findings(run),
        }

    @app.get("/api/dashboard")
    def api_dashboard() -> dict:
        """UI-02 health-at-a-glance aggregate: three traffic-light counters
        plus verification / correlation state distributions. Simple counts
        over the privileged-span index plane; no re-verification happens."""
        verif_dist: dict[str, int] = {}
        corr_dist: dict[str, int] = {}
        healthy = at_risk = needs = 0
        for run in data.runs:
            for trace in run["traces"]:
                for span in trace["spans"]:
                    if not span.get("privileged"):
                        continue
                    v = data.verification_for(span.get("receipt_hash"))
                    c = data.correlation_for_span(span, trace["trace_id"])
                    status, state = v["status"], c["state"]
                    verif_dist[status] = verif_dist.get(status, 0) + 1
                    corr_dist[state] = corr_dist.get(state, 0) + 1
                    if (
                        status in ("invalid", "unsupported_schema")
                        or state == "receipt_missing"
                    ):
                        needs += 1
                    elif (status == "valid" and state == "matched") or status == (
                        "not_applicable"
                    ):
                        healthy += 1
                    else:
                        # unknown_key / pending / unavailable / ambiguous /
                        # duplicate / late_arrival / matched_degraded /
                        # trace_missing / pending correlation — all un-proven.
                        at_risk += 1
        active = [f for f in data.findings if not f["suppressed"]]
        suppressed = len(data.findings) - len(active)
        return {
            "healthy": healthy,
            "at_risk": at_risk,
            "needs_investigation": needs + len(active),
            "verification_distribution": dict(sorted(verif_dist.items())),
            "correlation_distribution": dict(sorted(corr_dist.items())),
            "findings": {"active": len(active), "suppressed": suppressed},
            "runs": len(data.runs),
        }

    @app.get("/api/findings")
    def api_findings():
        return data.findings

    @app.get("/api/receipts/{receipt_hash}")
    def api_receipt(receipt_hash: str):
        meta = data.receipt_meta(receipt_hash)
        if meta is None:
            return JSONResponse({"error": "unknown receipt"}, status_code=404)
        return {
            **meta,
            "verification": data.verification_for(receipt_hash),
            "correlation": data.correlation_by_hash.get(receipt_hash),
            "jws": "available for download",  # never the value itself
            "jws_download": f"/api/receipts/{receipt_hash}/jws",
        }

    @app.get("/api/receipts/{receipt_hash}/jws")
    def api_jws(receipt_hash: str) -> Response:
        line = data.store_line(receipt_hash)
        if line is None:
            return JSONResponse(
                {"error": "no canonical envelope for this receipt"}, status_code=404
            )
        jws = json.loads(line)["jws"]
        return Response(
            content=jws,
            media_type="application/jwt",
            headers={"Content-Disposition": f'attachment; filename="{receipt_hash}.jws"'},
        )

    @app.post("/api/receipts/{receipt_hash}/verify")
    def api_verify(receipt_hash: str):
        line = data.store_line(receipt_hash)
        if line is None:
            return JSONResponse(
                {
                    "receipt_hash": receipt_hash,
                    "verification_status": "unavailable",
                    "detail": (
                        "no canonical envelope in the evidence store "
                        "(synthetic/demo index row) — offline classify not applicable"
                    ),
                    "checks_performed": [],
                    "verifier_available": True,
                },
                status_code=404,
                # status stays 404-able but body never fabricates a crypto verdict
            )
        return {"receipt_hash": receipt_hash, **verify_offline(line, data.trust_roots())}

    # ------------------------------------------------- optional live Langfuse
    @app.get("/api/live/traces")
    def api_live_traces() -> dict:
        base = os.environ.get("OAA_LANGFUSE_BASE_URL")
        public_key = os.environ.get("OAA_LANGFUSE_PUBLIC_KEY")
        secret_key = os.environ.get("OAA_LANGFUSE_SECRET_KEY")
        if not (base and public_key and secret_key):
            return {
                "available": False,
                "reason": "langfuse env not configured at runtime (skippable source)",
            }
        try:
            import httpx  # noqa: PLC0415

            resp = httpx.get(
                f"{base.rstrip('/')}/api/public/traces",
                auth=(public_key, secret_key),
                timeout=5.0,
            )
            resp.raise_for_status()
            payload = resp.json().get("data", [])
        except Exception as exc:
            return {"available": False, "reason": f"langfuse unavailable: {exc}"}
        # Minimal index-plane projection; content stays index-only.
        return {
            "available": True,
            "traces": [
                {
                    "trace_id": t.get("traceId"),
                    "name": t.get("name"),
                    "timestamp": t.get("timestamp"),
                }
                for t in payload[:20]
            ],
        }

    # --------------------------------------------- server-rendered (no-JS) views
    @app.get("/view/runs", response_class=HTMLResponse)
    def view_runs() -> str:
        rows = []
        for r in data.runs:
            s = _run_summary(r)
            rows.append(
                "<tr>"
                f"<td><a href='/view/run/{esc(r['run_id'])}'>{esc(r['run_id'])}</a></td>"
                f"<td>{esc(r['agent'])}</td><td>{esc(r['release'])}</td>"
                f"<td>{s['span_count']} ({s['privileged_span_count']} privileged)</td>"
                "<td>"
                + esc(", ".join(f"{k}:{v}" for k, v in sorted(s["verification_summary"].items())))
                + "</td><td>"
                + esc(", ".join(f"{k}:{v}" for k, v in sorted(s["correlation_summary"].items())))
                + "</td>"
                "</tr>"
            )
        return _page(
            "Runs",
            "<table><tr><th>run</th><th>agent</th><th>release</th><th>spans</th>"
            "<th>verification</th><th>correlation</th></tr>" + "".join(rows) + "</table>",
        )

    @app.get("/view/run/{run_id}", response_class=HTMLResponse)
    def view_run(run_id: str) -> str:
        run = data.get_run(run_id)
        if run is None:
            return _page("Runs", "<p>unknown run_id (escaped): " + esc(run_id) + "</p>")
        parts = []
        for trace in run["traces"]:
            corr = data.correlation_by_trace.get(trace["trace_id"])
            corr_state = corr["state"] if corr else "pending"
            cls = (
                "badge badge-unknown"
                if corr_state in ("receipt_missing", "trace_missing", "ambiguous", "pending")
                else "badge badge-ok"
            )
            parts.append(f"<h3>trace {esc(trace['trace_id'])} <span class='{cls}'>")
            parts.append(esc(corr_state) + "</span> — " + esc(trace["label"]) + "</h3>")
            parts.append(
                "<table><tr><th>span</th><th>tool</th><th>priv</th>"
                "<th>receipt_hash</th><th>verification</th><th>correlation</th></tr>"
            )
            for span in trace["spans"]:
                v = data.verification_for(span["receipt_hash"])
                c = data.correlation_for_span(span, trace["trace_id"])
                vc = "badge-unknown" if v["explicit_unknown"] else "badge-ok"
                cc = (
                    "badge-unknown"
                    if c["state"]
                    in (
                        "receipt_missing",
                        "trace_missing",
                        "ambiguous",
                        "duplicate",
                        "late_arrival",
                        "pending",
                    )
                    else "badge-ok"
                )
                note = esc(span["attrs"].get("oaa.note", "")) if span["attrs"] else ""
                parts.append(
                    "<tr>"
                    f"<td>{esc(span['name'])}</td><td>{esc(span['tool'] or '')}</td>"
                    f"<td>{'yes' if span['privileged'] else 'no'}</td>"
                    f"<td>{esc(span['receipt_hash'] or '— no receipt —')}</td>"
                    f"<td><span class='badge {vc}'>{esc(v['status'])}</span></td>"
                    f"<td><span class='badge {cc}'>{esc(c['state'])}</span></td>"
                    f"</tr><tr class='note'><td colspan='6'>note: {note}</td></tr>"
                )
            parts.append("</table>")
        findings = "".join(
            "<tr>"
            f"<td>{esc(f['rule_id'])}</td><td>{esc(f['severity'])}</td>"
            f"<td>{esc(f['confidence'])}</td><td>{esc(f['suppressed'])}</td>"
            f"<td>{esc(f['suppression_reason'] or '')}</td>"
            "</tr>"
            for f in _run_findings(run)
        )
        parts.append(
            "<h2>findings</h2><table><tr><th>rule</th><th>severity</th><th>confidence</th>"
            "<th>suppressed</th><th>suppression_reason</th></tr>" + findings + "</table>"
        )
        parts.append("<p><a href='/view/runs'>&larr; runs</a></p>")
        return _page(esc(run["run_id"]), "".join(parts))

    @app.get("/view/receipt/{receipt_hash}", response_class=HTMLResponse)
    def view_receipt(receipt_hash: str) -> str:
        meta = data.receipt_meta(receipt_hash)
        if meta is None:
            return _page("Evidence", "<p>unknown receipt (escaped): " + esc(receipt_hash) + "</p>")
        v = data.verification_for(receipt_hash)
        verify_btn = (
            "<form method='post' action='"
            f"/view/receipt/{esc(receipt_hash)}/verify'>"
            "<button type='submit'>Verify offline</button></form>"
            if meta["canonical"]
            else "<p>(no canonical envelope — offline verify not applicable)</p>"
        )
        jws = (
            f"<a href='/api/receipts/{esc(receipt_hash)}/jws' download>JWS available for "
            "download</a> (value never rendered)"
            if meta["jws_available"]
            else "<p>no JWS (synthetic index row)</p>"
        )
        body = (
            "<table>"
            f"<tr><th>receipt_hash</th><td>{esc(meta['receipt_hash'])}</td></tr>"
            f"<tr><th>schema_version</th><td>{esc(meta['schema_version'])}</td></tr>"
            f"<tr><th>gate decision</th><td>{esc(meta['decision'])}</td></tr>"
            f"<tr><th>policy_ref</th><td>{esc(meta['policy_ref'])}</td></tr>"
            f"<tr><th>tool</th><td>{esc(meta['tool'])}</td></tr>"
            f"<tr><th>trace_id</th><td>{esc(meta['trace_id'])}</td></tr>"
            "</table>"
            "<h2>verification</h2>"
            f"<p>status at ingest: <span class='badge"
            f" {'badge-unknown' if v['explicit_unknown'] else 'badge-ok'}'>"
            f"{esc(v['status'])}</span> — {esc(v['detail'])}</p>"
            f"<h2>offline verify</h2>{verify_btn}{jws}"
        )
        return _page("Evidence", body)

    @app.post("/view/receipt/{receipt_hash}/verify", response_class=HTMLResponse)
    def view_verify(receipt_hash: str) -> str:
        line = data.store_line(receipt_hash)
        if line is None:
            return _page(
                "Verify offline",
                "<p>no canonical envelope for "
                + esc(receipt_hash)
                + " — offline classify not applicable (explicit, not blank).</p>",
            )
        result = verify_offline(line, data.trust_roots())
        body = (
            f"<p>receipt_hash: {esc(receipt_hash)}</p>"
            "<p>verifier output summary:</p><pre>"
            + esc(
                json.dumps(
                    {k: result[k] for k in sorted(result) if k != "jws"},
                    indent=2,
                    sort_keys=True,
                )
            )
            + "</pre>"
            f"<p><a href='/view/receipt/{esc(receipt_hash)}'>&larr; evidence</a></p>"
        )
        return _page("Verify offline", body)

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(_static_dir / "index.html")  # UI-02 SPA

    @app.get("/legacy.html", include_in_schema=False)
    def legacy() -> FileResponse:
        return FileResponse(_static_dir / "legacy.html")  # UI-01 SPA, kept reachable

    return app


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<title>OAA investigation — " + title + "</title>"
        "<link rel='stylesheet' href='/static/styles.css'></head>"
        "<body><h1>Open Agent Assurance — " + title + "</h1>" + body + "</body></html>"
    )


app = create_app()
