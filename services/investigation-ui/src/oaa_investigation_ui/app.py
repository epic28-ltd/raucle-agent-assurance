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
  retained with suppression_reason (RULE-01);
- coverage (R1): GET /coverage/{org} — the receipted-share metric computed
  from the COR-01 correlation engine's own states over this instance's
  receipt/trace index plane (deterministic; unknown org renders 404
  unavailable, never a claimed zero).

Auth (R2 slice 1, via the shared oaa_hosted_auth package): when the
operator enables hosted OIDC (OAA_HOSTED_OIDC_ENABLED + issuer), operators
authenticate via their organisation's identity provider; sessions are
short-lived receipted bearers; a viewer/operator/security-admin role
ladder enforces a route-level permission matrix (fail-closed default
view-only), and mutating routes (ingest, triage, fleet writes) require
operator. With the feature off, legacy open behaviour is byte-identical.

UX hard rules (threat model T5):
- all model/tool content renders as hostile text (server-rendered views
  escape with html.escape; the SPA renders with textContent — no innerHTML);
- no auto-link resolution, no external fetches from the page, no secret
  display (JWS bodies, trust keys, env values never appear in output).
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import html
import json
import os
import pathlib
import re

import fastapi
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from . import assurance  # OV-2: packet/summary routes delegate to this module
from .counting import (  # noqa: F401
    BOARD_STATES,
    count_evidence,
    counts_payload,
    default_board_state,
    finding_lens,
    load_triage_states,
    now_iso,
)
from .data import DemoData, default_data_dir
from .fleet_rollup import (  # EPIC P2.C fleet rollup
    fleet_baseline,
    fleet_rollup,
    load_artifacts,
    parse_artifacts,
    persist_artifacts,
)
from .red_intake import (
    RED_LENS_BY_SEVERITY,
    RED_SOURCE,
    ingest_red_findings,
    load_red_findings,
    parse_findings_body,
    red_board_finding,
    validate_red_finding,
)
from .verify import verify_offline

TABLE_CLOSE = "</table>"

DATA_DIR = default_data_dir()
_static_dir = pathlib.Path(__file__).resolve().parents[2] / "static"


_FLEET_ROLLUP_PATH = "/api/fleet/rollup"


def _coverage_org() -> str:
    """Org id this assurance instance exposes coverage for.

    The deployment serves ONE org (this instance's ingested/observed data
    plane). The default ids the reference/demo deployment; an operator names
    their org with OAA_COVERAGE_ORG rather than silently serving another
    tenant's id under it.
    """
    return os.environ.get("OAA_COVERAGE_ORG", "demo")


def esc(value) -> str:
    """Hostile-text rendering: escape EVERYTHING; no link resolution."""
    return html.escape(str(value), quote=True)


# shared view-lens helpers (pure in `data`)


def _run_summary(data: DemoData, run: dict) -> dict:
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


def _run_findings(data: DemoData, run: dict) -> list[dict]:
    traces = {t["trace_id"] for t in run["traces"]}
    hashes = {s["receipt_hash"] for t in run["traces"] for s in t["spans"] if s["receipt_hash"]}
    out = []
    for f in data.findings:
        refs = set(f["evidence_refs"])
        if refs & traces or refs & hashes:
            out.append(f)
    return out


# ------------------------------------------------------------ API (JSON)


def _triage_state_path(base_dir: pathlib.Path) -> pathlib.Path:
    """Sidecar path, resolved and confined to the demo data directory.

    The data directory can come from the environment, so the resolved
    sidecar path must stay inside it before anything is read or written.
    """
    base = pathlib.Path(base_dir).resolve()
    path = (base / "triage_state.json").resolve()
    if not path.is_relative_to(base):
        raise ValueError(
            f"triage state path {str(path)!s} escapes the demo data dir "
            f"{str(base)!s}; refusing to use it"
        )
    return path


def _findings_age_seconds(f: dict) -> float | None:
    import datetime as dt  # noqa: PLC0415

    detected = f.get("detected_at")
    if not detected:
        return None
    return (dt.datetime.now(dt.UTC) - dt.datetime.fromisoformat(detected)).total_seconds()


def _trace_header_html(data: DemoData, trace: dict) -> list[str]:
    """Trace heading + correlation badge + the span-table header row."""
    corr = data.correlation_by_trace.get(trace["trace_id"])
    corr_state = corr["state"] if corr else "pending"
    cls = (
        "badge badge-unknown"
        if corr_state in ("receipt_missing", "trace_missing", "ambiguous", "pending")
        else "badge badge-ok"
    )
    return [
        f"<h3>trace {esc(trace['trace_id'])} <span class='{cls}'>",
        esc(corr_state) + "</span> — " + esc(trace["label"]) + "</h3>",
        (
            "<table><tr><th>span</th><th>tool</th><th>priv</th>"
            "<th>receipt_hash</th><th>verification</th><th>correlation</th></tr>"
        ),
    ]


def _span_row_html(data: DemoData, span: dict, trace_id: str) -> str:
    """One span row (plus its hostile-text note row) for the trace table."""
    v = data.verification_for(span["receipt_hash"])
    c = data.correlation_for_span(span, trace_id)
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
    return (
        "<tr>"
        f"<td>{esc(span['name'])}</td><td>{esc(span['tool'] or '')}</td>"
        f"<td>{'yes' if span['privileged'] else 'no'}</td>"
        f"<td>{esc(span['receipt_hash'] or '— no receipt —')}</td>"
        f"<td><span class='badge {vc}'>{esc(v['status'])}</span></td>"
        f"<td><span class='badge {cc}'>{esc(c['state'])}</span></td>"
        f"</tr><tr class='note'><td colspan='6'>note: {note}</td></tr>"
    )


def index() -> FileResponse:
    return FileResponse(_static_dir / "index.html")  # UI-02 SPA


def legacy() -> FileResponse:
    return FileResponse(_static_dir / "legacy.html")  # UI-01 SPA, kept reachable


def fleet() -> FileResponse:
    return FileResponse(_static_dir / "fleet.html")  # EPIC P2.C fleet view


class _Routes:
    """Endpoint logic for UI-01; bodies live here so ``create_app`` stays a
    pure router registration (S3776): no counting logic in the factory."""

    def __init__(self, data_dir: pathlib.Path) -> None:
        self.data_dir = data_dir
        self.data = DemoData(self.data_dir)

    # ------------------------------------------------------------ API (JSON)
    def runs(self):
        return [
            {
                **{k: r[k] for k in ("run_id", "agent", "release", "started")},
                **_run_summary(self.data, r),
            }
            for r in self.data.runs
        ]

    def run(self, run_id: str):
        run = self.data.get_run(run_id)
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
                        "verification": self.data.verification_for(span.get("receipt_hash")),
                        "correlation": self.data.correlation_for_span(span, trace["trace_id"]),
                        "evidence_canonical": bool(
                            self.data.store_line(span.get("receipt_hash") or "")
                            if span["receipt_hash"]
                            else False
                        ),
                    }
                )
            corr = self.data.correlation_by_trace.get(trace["trace_id"])
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
            **_run_summary(self.data, run),
            "traces": traces,
            "findings": _run_findings(self.data, run),
        }

    def dashboard(self) -> dict:
        """UI-02 health-at-a-glance aggregate: three traffic-light counters
        plus verification / correlation state distributions. Every number
        comes from the shared counting module (one source, both surfaces);
        no counting logic lives here any more."""
        counts = counts_payload(self.data_dir, self.data)
        active = counts["findings"]["active"]
        suppressed = counts["findings"]["suppressed"]
        return {
            "healthy": counts["health"]["healthy"],
            "at_risk": counts["health"]["at_risk"],
            "needs_investigation": counts["health"]["needs_investigation"],
            "verification_distribution": counts["verification"]["states"],
            "correlation_distribution": counts["correlation"]["states"],
            "buckets": counts["verification"]["buckets"],
            "findings": {"active": active, "suppressed": suppressed},
            "runs": counts["runs"],
        }

    def counts(self) -> dict:
        """UI-05 coherence pass: ONE full breakdown of every count both
        surfaces render, computed from the same demo self.data source by the
        shared counting module. The board, the dashboard and the console
        (via its proxy) all read from exactly this output."""
        return counts_payload(self.data_dir, self.data)

    def findings(self):
        return self.data.findings

    # ---------------------------------------------- RED-INTEGRATION intake
    async def ingest_findings(self, request: fastapi.Request):
        """Accepts red findings at run end (see red_intake + the spike doc).
        Body: a JSON array of findings, an ``{"findings": [...]}`` object, or
        raw JSONL text — the exact shape of ``corpora/findings.jsonl``.
        Validated against the red schema (deterministic UUID5 finding_id,
        severity enum, sha256 evidence integrity re-verified for local path
        references); merged idempotently into the ``red_findings.json``
        sidecar so re-posting a run is a no-op. The canonical evidence store
        is never touched."""
        body_bytes = await request.body()
        try:
            payload = json.loads(body_bytes.decode("utf-8")) if body_bytes else None
        except ValueError:
            payload = None
        try:
            findings = parse_findings_body(body_bytes.decode("utf-8", "replace"), payload)
            for raw in findings:
                validate_red_finding(raw)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=422)
        if not findings:
            return JSONResponse({"error": "no findings in body"}, status_code=422)
        summary = ingest_red_findings(self.data.dir, findings)
        return {"ingested": True, "source": RED_SOURCE, **summary}

    def red_findings(self):
        """The ingested red slice (source-tagged 'red-mvp'), board-shaped."""
        return {
            "source": RED_SOURCE,
            "by_severity": self._red_counts(),
            "findings": [red_board_finding(r) for r in load_red_findings(self.data.dir)],
        }

    def _red_counts(self) -> dict:
        from .red_intake import RED_SEVERITIES  # noqa: PLC0415

        counts = dict.fromkeys(RED_SEVERITIES, 0)
        for r in load_red_findings(self.data.dir):
            counts[r["severity"]] = counts.get(r["severity"], 0) + 1
        return counts

    # ------------------------------------------------- UI-02.4 findings board
    def _load_triage_states(self) -> dict:
        """Board triage overrides, persisted as a UI-sidecar index (never the
        canonical evidence store). Default state derives from the finding:
        fixture-suppressed findings sit in the Suppressed column, everything
        else is untriaged (New)."""
        return load_triage_states(self.data.dir)

    def _board_findings(self) -> tuple[list[dict], dict]:
        states = self._load_triage_states()
        red_rows = [red_board_finding(r) for r in load_red_findings(self.data.dir)]
        red_ids = {f["id"] for f in red_rows}
        findings = []
        for f in [*self.data.findings, *red_rows]:
            st = states.get(f["id"]) or default_board_state(f)
            if st not in BOARD_STATES:
                st = default_board_state(f)
            findings.append(_board_row(f, st, red_ids, _findings_age_seconds(f)))
        # KPI values are the counting module's finding-lens counts, so every
        # KPI number equals its own chip count and column/member count:
        # verified stays an explicit index-plane metric (valid bucket).
        counts = counts_payload(self.data_dir, self.data)
        lens = counts["findings"]["lens"]
        kpis = {
            "needs_investigation": lens["needs_investigation"],
            "unproven": lens["unproven"],
            "coverage_gaps": lens["coverage_gaps"],
            "verified": counts["verification"]["buckets"]["valid"],
            "verified_total": counts["verification"]["total"],
        }
        return findings, kpis

    def findings_board(self):
        findings, kpis = self._board_findings()
        by_state = dict.fromkeys(BOARD_STATES, 0)
        for f in findings:
            by_state[f["state"]] += 1
        return {
            "kpis": kpis,
            "columns": by_state,
            "states": BOARD_STATES,
            "findings": findings,
        }

    def triage(self, finding_id: str, body: dict):
        """Alpha board-state persistence: cycles 'New -> Investigating ->
        Resolved' (click the state button per card; see the spike). Writes a
        sidecar ``triage_state.json`` in the demo self.data dir — the canonical
        evidence store stays untouched (invariant 1)."""
        # finding_id arrives from request content, so it is format-checked
        # before it can index the sidecar state file: only the finding-id
        # charset is accepted, and anything aiming at a path element ("..
        # ", separators) is rejected outright.
        finding_id_ok = re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", finding_id)
        if finding_id_ok is None or ".." in finding_id:
            return JSONResponse({"error": "malformed finding id"}, status_code=422)
        if not any(f["id"] == finding_id for f in self.data.findings):
            return JSONResponse({"error": "unknown finding id"}, status_code=404)
        state = str(body.get("state", ""))
        if state not in BOARD_STATES:
            return JSONResponse(
                {"error": "state must be one of " + ", ".join(BOARD_STATES)},
                status_code=422,
            )
        path = _triage_state_path(self.data.dir)
        current = {}
        try:
            current = json.loads(path.read_text()) if path.is_file() else {}
        except (OSError, ValueError):
            current = {}
        known_ids = {f["id"] for f in self.data.findings}
        current = {k: v for k, v in current.items() if isinstance(k, str) and k in known_ids}
        current[finding_id] = state
        # Suppression rationale: read-modify-write of the sidecar itself. The
        # path is confined by _triage_state_path and the only content written
        # is this file's own JSON merged with one enum-valued key. See
        # docs/spikes/SONAR-ACCEPTANCE.md (S2083).
        path.write_text(json.dumps(current, indent=2, sort_keys=True))  # NOSONAR
        return {"id": finding_id, "state": state}

    def receipt(self, receipt_hash: str):
        meta = self.data.receipt_meta(receipt_hash)
        if meta is None:
            return JSONResponse({"error": "unknown receipt"}, status_code=404)
        return {
            **meta,
            "verification": self.data.verification_for(receipt_hash),
            "correlation": self.data.correlation_by_hash.get(receipt_hash),
            "jws": "available for download",  # never the value itself
            "jws_download": f"/api/receipts/{receipt_hash}/jws",
        }

    def jws(self, receipt_hash: str) -> Response:
        line = self.data.store_line(receipt_hash)
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

    def verify_receipt(self, receipt_hash: str):
        line = self.data.store_line(receipt_hash)
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
        return {"receipt_hash": receipt_hash, **verify_offline(line, self.data.trust_roots())}

    # ------------------------------------------------- OV-2 assurance packet
    def assurance_packet(self, body: dict | None = None):
        try:
            refs = assurance.body_refs(body)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=422)
        packet, error = self._build_packet_or_error(refs)
        if error is not None:
            return error
        return JSONResponse(
            packet,
            headers={"Content-Disposition": ('attachment; filename="agent_assurance_packet.json"')},
        )

    def assurance_summary(self) -> Response:
        _packet, error = self._build_packet_or_error()
        if error is not None:
            return error
        return HTMLResponse(assurance.html_for(self.data_dir))

    def _build_packet_or_error(self, refs: dict | None = None):
        # Named missing-store check before delegating: DemoData guarantees a
        # store at load, so a store that has vanished since (or a test-built
        # dir without one) must surface as the CLI's own named 404-class
        # error, never a fabricated packet.
        store = self.data_dir.resolve() / assurance.STORE_FILE
        if not store.is_file():
            return None, JSONResponse(
                {"error": f"evidence store not found: {store}"}, status_code=404
            )
        try:
            refs = refs if refs is not None else {}
            return assurance.build_from_store(self.data_dir, refs), None
        except ValueError as exc:
            return None, self._packet_error(exc)

    @staticmethod
    def _packet_error(exc: ValueError) -> Response:
        """CLI fail-visible semantics as HTTP: missing store is 404-class,
        every other named error (tampered, malformed, bad refs) is 422."""
        text = str(exc)
        if "not found" in text:
            return JSONResponse({"error": text}, status_code=404)
        return JSONResponse({"error": text}, status_code=422)

    # ------------------------------------------------- optional live Langfuse
    # --------------------------------------------- EPIC P2.C fleet rollup
    def fleet_view(self) -> dict:
        """The ONE fleet view: per-gate rollup plus F2 baseline status,
        both computed from persisted gate artifacts by the fleet module.
        A gate that never shipped an artifact simply does not appear; a
        gate that shipped one without figures renders ABSENT, never zero."""
        artifacts = load_artifacts(self.data_dir)
        return {
            "rollup": fleet_rollup(artifacts),
            "baseline": fleet_baseline(artifacts),
        }

    async def fleet_ingest(self, request: fastapi.Request):
        """Ingest per-gate artifacts (gate_id required; board JSON export,
        F2 baseline status and as-reported coverage all optional). Stored
        in the fleet sidecar — the canonical evidence store stays untouched."""
        body_bytes = await request.body()
        try:
            raw = json.loads(body_bytes.decode("utf-8")) if body_bytes else None
        except ValueError:
            raw = None
        try:
            artifacts = parse_artifacts(raw)
        except ValueError as exc:
            return JSONResponse({"error": str(exc)}, status_code=422)
        existing = load_artifacts(self.data_dir)
        by_id = {a["gate_id"]: a for a in existing}
        for a in artifacts:
            by_id[a["gate_id"]] = a
        merged = [by_id[k] for k in sorted(by_id)]
        persist_artifacts(self.data_dir, merged)
        return {"ingested": True, "gates": len(merged)}

    def fleet_reset(self):
        """Drop persisted gate artifacts (sidecar only; ingest is idempotent
        per gate_id so re-posting restores everything it carried)."""
        persist_artifacts(self.data_dir, [])
        return {"fleet": "reset"}

    def coverage(self, org: str):
        """R1: the receipted-share coverage metric (GET /coverage/{org}).

        Computed from the COR-01 correlation engine's own terminal states
        over this instance's receipt/trace index plane — deterministic
        (``at=None``: reconciled as if every window had closed; no wall
        clock enters the number). Data an org does not hold is 404 with the
        gap named: coverage for an org with no observed actions is
        UNAVAILABLE, never zero (absence is a first-class state, and zero
        would claim evidence that does not exist).
        """
        known = _coverage_org()
        if org != known:
            return JSONResponse(
                {
                    "org": org,
                    "error": (
                        f"no observed agent actions recorded for org {org!r}; "
                        "coverage is unavailable here, never zero"
                    ),
                    "known_orgs": [known],
                },
                status_code=404,
            )
        # R1 metric lives in the correlation engine; ``.data`` (imported at
        # module top) has already put the correlation service src on
        # sys.path — the repo's importability convention for cross-service
        # modules keeps this import inside the request path.
        from oaa_correlation import coverage  # noqa: PLC0415

        payload = coverage(self.data.receipt_records, self.data.trace_records, at=None)
        return {
            "org": org,
            "basis": (
                "observed agent actions = ADR-0002 trace-side records; "
                "receipts counted via correlated x_gate.trace_id only"
            ),
            **payload,
        }

    def live_traces(self) -> dict:
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
            payload = resp.json().get("self.data", [])
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
    def view_runs(self) -> str:
        rows = []
        for r in self.data.runs:
            s = _run_summary(self.data, r)
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
            "<th>verification</th><th>correlation</th></tr>" + "".join(rows) + TABLE_CLOSE,
        )

    def view_run(self, run_id: str) -> str:
        run = self.data.get_run(run_id)
        if run is None:
            return _page("Runs", "<p>unknown run_id (escaped): " + esc(run_id) + "</p>")
        parts = []
        for trace in run["traces"]:
            parts.extend(_trace_header_html(self.data, trace))
            for span in trace["spans"]:
                parts.append(_span_row_html(self.data, span, trace["trace_id"]))
            parts.append(TABLE_CLOSE)
        findings = "".join(
            "<tr>"
            f"<td>{esc(f['rule_id'])}</td><td>{esc(f['severity'])}</td>"
            f"<td>{esc(f['confidence'])}</td><td>{esc(f['suppressed'])}</td>"
            f"<td>{esc(f['suppression_reason'] or '')}</td>"
            "</tr>"
            for f in _run_findings(self.data, run)
        )
        parts.append(
            "<h2>findings</h2><table><tr><th>rule</th><th>severity</th><th>confidence</th>"
            "<th>suppressed</th><th>suppression_reason</th></tr>" + findings + TABLE_CLOSE
        )
        parts.append("<p><a href='/view/runs'>&larr; runs</a></p>")
        return _page(esc(run["run_id"]), "".join(parts))

    def view_receipt(self, receipt_hash: str) -> str:
        meta = self.data.receipt_meta(receipt_hash)
        if meta is None:
            return _page("Evidence", "<p>unknown receipt (escaped): " + esc(receipt_hash) + "</p>")
        v = self.data.verification_for(receipt_hash)
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
            f"{TABLE_CLOSE}"
            "<h2>verification</h2>"
            f"<p>status at ingest: <span class='badge"
            f" {'badge-unknown' if v['explicit_unknown'] else 'badge-ok'}'>"
            f"{esc(v['status'])}</span> — {esc(v['detail'])}</p>"
            f"<h2>offline verify</h2>{verify_btn}{jws}"
        )
        return _page("Evidence", body)

    def view_verify(self, receipt_hash: str) -> str:
        line = self.data.store_line(receipt_hash)
        if line is None:
            return _page(
                "Verify offline",
                "<p>no canonical envelope for "
                + esc(receipt_hash)
                + " — offline classify not applicable (explicit, not blank).</p>",
            )
        result = verify_offline(line, self.data.trust_roots())
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


def create_app(
    data_dir: pathlib.Path | None = None,
    hosted=None,
    *,
    env: dict[str, str] | None = None,
    http_get=None,
    http_post_form=None,
    clock=None,
) -> fastapi.FastAPI:
    """Build the FastAPI app; each route binds to a shared _Routes view.

    ``hosted`` may be a pre-built :class:`oaa_hosted_auth.HostedAuth`
    (tests inject the provider transport there); when omitted, the surface
    boots from the environment. Fail-closed: an enabled but misconfigured
    or unreachable provider refuses the app entirely.
    """
    from oaa_hosted_auth import WRITE  # noqa: PLC0415

    if hosted is None:
        from oaa_hosted_auth import HostedAuth  # noqa: PLC0415

        service_dir = pathlib.Path(__file__).resolve().parents[2]
        hosted = HostedAuth.boot(
            "assurance",
            default_state_dir=str(service_dir / ".hosted-state"),
            env=env,
            http_get=http_get,
            http_post_form=http_post_form,
            clock=clock,
        )
    app = fastapi.FastAPI(title="OAA Investigation UI (UI-01)", version="0.1.0")
    api = _Routes(data_dir or DATA_DIR)

    # ------------------------------------------------------------ API (JSON)
    # Every route binds its R2 permission-matrix capability (route-level
    # enforcement in enabled mode; legacy open mode when auth is off).
    hosted.bind(app, "/api/runs", api.runs)
    hosted.bind(app, "/api/runs/{run_id}", api.run)
    hosted.bind(app, "/api/dashboard", api.dashboard)
    hosted.bind(app, "/api/counts", api.counts)
    hosted.bind(app, "/api/findings", api.findings)
    # ---------------------------------------------- RED-INTEGRATION intake
    hosted.bind(
        app, "/api/findings/ingest", api.ingest_findings, methods=("POST",), capability=WRITE
    )
    hosted.bind(app, "/api/findings/red", api.red_findings)
    # ------------------------------------------------- UI-02.4 findings board
    hosted.bind(app, "/api/findings/board", api.findings_board)
    hosted.bind(
        app, "/api/findings/{finding_id}/triage", api.triage, methods=("POST",), capability=WRITE
    )
    # --------------------------------------------- EPIC P2.C fleet rollup
    hosted.bind(app, _FLEET_ROLLUP_PATH, api.fleet_view)
    hosted.bind(app, _FLEET_ROLLUP_PATH, api.fleet_ingest, methods=("POST",), capability=WRITE)
    hosted.bind(app, _FLEET_ROLLUP_PATH, api.fleet_reset, methods=("DELETE",), capability=WRITE)
    # ------------------------------------------------- R1 coverage metric
    hosted.bind(app, "/coverage/{org}", api.coverage)
    hosted.bind(app, "/api/receipts/{receipt_hash}", api.receipt)
    hosted.bind(app, "/api/receipts/{receipt_hash}/jws", api.jws)
    hosted.bind(app, "/api/receipts/{receipt_hash}/verify", api.verify_receipt, methods=("POST",))
    # ------------------------------------------------- optional live Langfuse
    hosted.bind(app, "/api/live/traces", api.live_traces)
    # ---------------------------------------------------- OV-2 assurance packet
    hosted.bind(app, "/assurance/packet", api.assurance_packet, methods=("POST",))
    hosted.bind(app, "/assurance/summary", api.assurance_summary, response_class=HTMLResponse)
    # --------------------------------------------- server-rendered (no-JS) views
    # Data pages fail closed as an HTML login-required page (they are a
    # human surface, so the refusal is human, not the JSON shape).
    hosted.bind(app, "/view/runs", api.view_runs, response_class=HTMLResponse, html_denied=True)
    hosted.bind(
        app,
        "/view/run/{run_id}",
        api.view_run,
        response_class=HTMLResponse,
        html_denied=True,
    )
    hosted.bind(
        app,
        "/view/receipt/{receipt_hash}",
        api.view_receipt,
        response_class=HTMLResponse,
        html_denied=True,
    )
    hosted.bind(
        app,
        "/view/receipt/{receipt_hash}/verify",
        api.view_verify,
        methods=("POST",),
        response_class=HTMLResponse,
        html_denied=True,
    )
    hosted.register_shared_routes(app)
    # The default-deny net: enabled mode refuses every unbound path.
    # Exemptions are the data-free shells only (index/legacy/fleet SPA HTML).
    hosted.install_net(
        app, exempt_exact=("/", "/legacy.html", "/view/fleet"), exempt_prefixes=("/static/",)
    )
    app.get("/", include_in_schema=False)(index)
    app.get("/legacy.html", include_in_schema=False)(legacy)
    app.get("/view/fleet", include_in_schema=False, response_class=FileResponse)(fleet)
    return app


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<title>OAA investigation — " + title + "</title>"
        "<link rel='stylesheet' href='/static/styles.css'></head>"
        "<body><h1>Open Agent Assurance — " + title + "</h1>" + body + "</body></html>"
    )


app = create_app()


def _board_row(f: dict, st: str, red_ids: set[str], age_seconds: float | None) -> dict:
    """Board row assembly for one finding or RED intake row (pure)."""
    is_red = f["id"] in red_ids
    detected = f.get("detected_at")
    return {
        "id": f["id"],
        "rule_id": f["rule_id"],
        "severity": f["severity"],
        "confidence": f["confidence"],
        "explanation": f["explanation"],
        "subject": f["subject"],
        "evidence_refs": f["evidence_refs"],
        "primary_ref": f["evidence_refs"][0] if f["evidence_refs"] else "",
        "suppressed": f["suppressed"],
        "suppression_reason": f["suppression_reason"],
        "detected_at": detected,
        "age_seconds": round(age_seconds) if age_seconds is not None else None,
        "run_id": f.get("run_id"),
        "state": st,
        "lens": (
            RED_LENS_BY_SEVERITY[f["severity"]]
            if is_red
            else finding_lens(f)  # shared taxonomy (counting module)
        ),
        # RED-INTEGRATION: source chip ('assurance' vs 'red-mvp')
        # and per-rule guidance text — red rules are unknown to the static G
        # map, so red rows carry a guidance string from red_intake directly
        # (generic fallback included).
        "source": RED_SOURCE if is_red else "assurance",
        "guidance": f.get("guidance") if is_red else None,
    }
