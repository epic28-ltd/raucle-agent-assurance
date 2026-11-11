"""Shared counting module — ONE source for every number on both surfaces.

The QA coherence pass (docs/spikes/coherence-pass.md) found count
incoherence within the findings board (KPI number vs its own chip, scope
chips vs column badges, two taxonomies) and across the two surfaces
(console traffic-light figures vs board figures). A verification product
must have numbers that agree.

This module computes every bucket from the SAME demo data source, exactly
once, and both services read only from its output:

- the investigation UI exposes ``GET /api/counts`` (full breakdown) and
  derives its board KPIs and dashboard traffic lights from it;
- the console imports ``count_evidence`` for its /api/overview trust
  figures and its offline fallbacks — it never computes its own numbers.

Bucket taxonomies (documented in docs/spikes/coherence-pass.md and
docs/spikes/UI-02.4-findings-board.md):

- Verification (privileged-span index plane, ADR-0001 states folded):
    valid       = valid
    unproven    = unknown_key + pending            (amber semantics)
    unaccounted = unsupported_schema + invalid     (action semantics)
    exempt      = unavailable + not_applicable     (grey semantics)
  The raw per-state map is carried alongside, so nothing is hidden.

- Correlation (ADR-0002 states, same span plane): all eight states are
  materialised (zeros included) so the map is always complete.

- Findings triage (rules engine findings with board state from the
  sidecar triage index):
    open lens partition: needs_investigation / unproven / coverage_gaps
    plus open (= sum of the three) + closed + suppressed, reconciling:
    open + closed + suppressed == total.

  RED-INTEGRATION: ingested red findings (``red_findings.json`` sidecar)
  are folded into the same partition — total = assurance findings +
  red ingested, no double-counting. Red rows have no SEC rule semantics,
  so their risk lens folds by severity (documented in red_intake.py +
  docs/spikes/RED-INTEGRATION-findings.md): critical/high →
  needs_investigation, medium/low → unproven, info → unproven. Their
  share is reported separately under the ``red`` key (never re-counted).
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import datetime as dt
import json
import pathlib

from .data import DemoData, default_data_dir

# ---------------------------------------------------------------- taxonomies
VERIFICATION_BUCKETS = ("valid", "unproven", "unaccounted", "exempt")
CORRELATION_STATES = (
    "matched",
    "matched_degraded",
    "ambiguous",
    "duplicate",
    "late_arrival",
    "receipt_missing",
    "trace_missing",
    "pending",
)
FINDING_LENS = ("needs_investigation", "unproven", "coverage_gaps")

# Board short lens -> canonical count lens (single translation point;
# red_intake emits the board vocabulary, counting folds on canonical names).
_RED_LENS_CANONICAL = {"needs": "needs_investigation", "gaps": "coverage_gaps"}

# Board lifecycle states (single taxonomy, shared with app.py): 'closed'
# replaces the earlier 'resolved' label everywhere.
BOARD_STATES = ("new", "investigating", "suppressed", "closed")

# Risk lens over findings, derived from rule semantics: needs = discrepancy
# needing an investigator decision; unproven = evidence present, less than
# full proof; coverage_gaps = absence rules (SEC-001 / SEC-007).
LENS_BY_RULE = {
    "SEC-004": "needs",
    "SEC-008": "needs",
    "SEC-009": "needs",
    "SEC-010": "needs",
    "SEC-002": "unproven",
    "SEC-003": "unproven",
    "SEC-005": "unproven",
    "SEC-006": "unproven",
    "SEC-011": "unproven",
    "SEC-001": "gaps",
    "SEC-007": "gaps",
}

_LENS_KEYS = {"needs": "needs_investigation", "unproven": "unproven", "gaps": "coverage_gaps"}


def finding_lens(f: dict) -> str:
    """Risk lens for one finding (needs / unproven / gaps)."""
    return LENS_BY_RULE.get(f["rule_id"], "unproven")


# ------------------------------------------------------------ data loading
_CACHE: dict[tuple, tuple[float, DemoData]] = {}


def load_cached(data_dir: pathlib.Path) -> DemoData:
    """DemoData cache keyed by path + dir mtime, so per-request counting does
    not re-run the correlation engine on unchanged fixtures (triage-sidecar
    state is re-read on every count regardless)."""
    data_dir = pathlib.Path(data_dir)
    stamp = (data_dir / "evidence_store.jsonl").stat().st_mtime_ns
    key = (str(data_dir), stamp)
    hit = _CACHE.get(key)
    if hit is None:
        hit = _CACHE[key] = data_dir.stat(), DemoData(data_dir)  # type: ignore[assignment]
    return hit[1]


def _triage_states(data_dir: pathlib.Path) -> dict[str, str]:
    path = pathlib.Path(data_dir) / "triage_state.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def load_triage_states(data_dir: pathlib.Path) -> dict[str, str]:
    """Board triage overrides from the sidecar index in the data dir
    (never the canonical evidence store)."""
    return _triage_states(data_dir)


def default_board_state(f: dict) -> str:
    return "suppressed" if f["suppressed"] else "new"


def counts_payload(data_dir: pathlib.Path | None = None, data: DemoData | None = None) -> dict:
    """count_evidence with the current server moment recorded."""
    return count_evidence(data_dir or default_data_dir(), at=now_iso(), data=data)


# ------------------------------------------------------------------ counts
def _privileged_plane_counts(data: DemoData) -> tuple[dict, dict, int, int, int]:
    """One row per privileged span: verification/correlation state counts and
    the healthy / at_risk / needs_investigation totals."""
    verif_states: dict[str, int] = {}
    corr_states: dict[str, int] = dict.fromkeys(CORRELATION_STATES, 0)
    healthy = at_risk = needs = 0
    for run in data.runs:
        for trace in run["traces"]:
            for span in trace["spans"]:
                if not span.get("privileged"):
                    continue
                v = data.verification_for(span.get("receipt_hash"))
                c = data.correlation_for_span(span, trace["trace_id"])
                verif_states[v["status"]] = verif_states.get(v["status"], 0) + 1
                corr_states[c["state"]] = corr_states.get(c["state"], 0) + 1
                healthy, at_risk, needs = _healthy_at_risk_needs(
                    v["status"], c["state"], healthy, at_risk, needs
                )
    return verif_states, corr_states, healthy, at_risk, needs


def _healthy_at_risk_needs(
    v_status: str, c_state: str, healthy: int, at_risk: int, needs: int
) -> tuple[int, int, int]:
    """Bucket one privileged span; unknown/pending states stay un-proven."""
    if v_status in ("invalid", "unsupported_schema") or c_state == "receipt_missing":
        needs += 1
    elif (v_status == "valid" and c_state == "matched") or v_status == "not_applicable":
        healthy += 1
    else:
        # unknown_key / pending / unavailable / ambiguous /
        # duplicate / late_arrival / matched_degraded /
        # trace_missing / pending correlation — all un-proven.
        at_risk += 1
    return healthy, at_risk, needs


def _finding_lens_and_states(data_dir: pathlib.Path, all_findings: list[dict]) -> tuple[dict, dict]:
    """Finding-lens and board-state counts over the merged finding list."""
    from .red_intake import RED_LENS_BY_SEVERITY, RED_SOURCE  # noqa: PLC0415

    lens_counts: dict[str, int] = dict.fromkeys(FINDING_LENS, 0)
    state_counts: dict[str, int] = dict.fromkeys(BOARD_STATES, 0)
    states = _triage_states(data_dir)
    for f in all_findings:
        st = states.get(f["id"]) or default_board_state(f)
        if st not in BOARD_STATES:
            st = default_board_state(f)
        state_counts[st] += 1
        if st in ("new", "investigating"):
            if f.get("source") == RED_SOURCE:
                # red_intake emits the board's short lens vocabulary; the
                # canonical count set uses full names, so translate here.
                lens_counts[
                    _RED_LENS_CANONICAL.get(
                        RED_LENS_BY_SEVERITY[f["severity"]],
                        RED_LENS_BY_SEVERITY[f["severity"]],
                    )
                ] += 1
            else:
                lens_counts[_LENS_KEYS[finding_lens(f)]] += 1
    return lens_counts, state_counts


def count_evidence(
    data_dir: pathlib.Path | None = None,
    at: str | None = None,
    data: DemoData | None = None,
) -> dict:
    """ONE function: every count both surfaces show, from the same source.

    ``at`` is an optional reconciliation moment (ISO-8601) recorded in the
    payload; ``data`` lets an already-loaded DemoData be reused (the app
    passes its own), otherwise a cached load is used.
    """
    data_dir = pathlib.Path(data_dir) if data_dir else default_data_dir()
    if data is None:
        data = load_cached(data_dir)

    # ---------------------------------------------- verification / correlation
    # The privileged-span index plane: one row per privileged span. These
    # same loops previously lived in app.py (dashboard) AND in the board
    # KPI code — now they live here, once.
    verif_states, corr_states, healthy, at_risk, needs = _privileged_plane_counts(data)
    ver_total = sum(verif_states.values())
    buckets = {
        "valid": verif_states.get("valid", 0),
        "unproven": verif_states.get("unknown_key", 0) + verif_states.get("pending", 0),
        "unaccounted": verif_states.get("unsupported_schema", 0) + verif_states.get("invalid", 0),
        "exempt": verif_states.get("unavailable", 0) + verif_states.get("not_applicable", 0),
    }
    assert sum(buckets.values()) == ver_total  # buckets partition the plane

    # ---------------------------------------------------------------- findings
    # Ingested red findings (RED-INTEGRATION) fold into the same single loop:
    # they come from the ``red_findings.json`` sidecar, are projected onto the
    # board shape by red_intake, and take their risk lens from severity
    # (critical/high → needs, medium/low → unproven, info → unproven):
    #   Severity mapping — red has no rule semantics in the assurance G map,
    #   so the fold is by severity only: critical/high are discrepancies
    #   needing an investigator decision; medium/low and info are assurance
    #   claims that are present-but-not-yet-judged (unproven). No red finding
    #   ever lands in coverage_gaps (a red probe is presence, not an absence
    #   rule). Totals stay one partition: assurance + red == total, and
    #   open + closed + suppressed == total holds over the merged list.
    from .red_intake import (  # noqa: PLC0415
        RED_SEVERITIES,
        load_red_findings,
        red_board_finding,
    )

    red_rows = [red_board_finding(r) for r in load_red_findings(data_dir)]
    red_by_severity: dict[str, int] = dict.fromkeys(RED_SEVERITIES, 0)
    for r in red_rows:
        red_by_severity[r["severity"]] += 1
    red_total = len(red_rows)
    all_findings = [*data.findings, *red_rows]
    lens_counts, state_counts = _finding_lens_and_states(data_dir, all_findings)
    open_total = sum(lens_counts.values())
    total_findings = len(all_findings)
    assert open_total + state_counts["closed"] + state_counts["suppressed"] == total_findings
    assert sum(red_by_severity.values()) == red_total

    # ------------------------------------------------ receipts (index plane) facts
    verif_rows = list(data._verif.values())
    synth = _synthetic_rows(data_dir)
    receipts_index = set(data._store_index) | {r["receipt_hash"] for r in synth}
    return {
        "schema_version": 1,
        "at": at,
        "runs": len(data.runs),
        "verification": {
            "total": ver_total,
            "states": dict(sorted(verif_states.items())),
            "buckets": buckets,
        },
        "correlation": {
            "total": ver_total,
            "states": dict(sorted(corr_states.items())),
        },
        "health": {"healthy": healthy, "at_risk": at_risk, "needs_investigation": needs},
        "triaged_findings": {
            "total": total_findings,
            "states": state_counts,
            "lens": {**lens_counts, "open": open_total},
        },
        "findings": {  # dashboard-shaped alias kept for the console proxy
            "total": total_findings,
            "active": total_findings - state_counts["suppressed"],
            "suppressed": state_counts["suppressed"],
            "closed": state_counts["closed"],
            "lens": {
                "needs_investigation": lens_counts["needs_investigation"],
                "unproven": lens_counts["unproven"],
                "coverage_gaps": lens_counts["coverage_gaps"],
                "open": open_total,
                "closed": state_counts["closed"],
                "suppressed": state_counts["suppressed"],
            },
        },
        # RED-INTEGRATION: ingested red findings are counted once, inside the
        # loop above (folded by severity into the lens); this section reports
        # their share so the board and console can show the red slice
        # without re-counting or double-counting them.
        "red": {"ingested": red_total, "by_severity": red_by_severity},
        "assurance_findings_total": total_findings - red_total,
        "red_total": red_total,
        "trust": {
            "receipts_minted": len(receipts_index),
            "verification_rows": len(verif_rows),
            "verification_valid": sum(1 for r in verif_rows if r["status"] == "valid"),
        },
    }


def _synthetic_rows(data_dir: pathlib.Path) -> list[dict]:
    rows = []
    for ln in _synthetic_lines(data_dir):
        row = json.loads(ln)
        if row.get("synthetic"):
            rows.append(row)
    return rows


def _synthetic_lines(data_dir: pathlib.Path) -> list[str]:
    path = pathlib.Path(data_dir) / "synthetic_receipt_index.jsonl"
    if not path.is_file():
        return []
    return [ln for ln in path.read_text().splitlines() if ln.strip() and not ln.startswith("#")]


def now_iso() -> str:
    return dt.datetime.now(dt.UTC).isoformat()
