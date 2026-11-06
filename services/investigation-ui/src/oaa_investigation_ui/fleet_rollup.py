# SPDX-License-Identifier: Apache-2.0
"""Fleet rollup (EPIC P2.C1) — per-gate coverage and status on ONE honest view.

Inputs are per-gate artifacts, each carrying exactly what its gate actually
reported:

- ``gate_id``        (required, charset-validated) — which gate the artifact covers;
- ``board``          (optional) the runs/latest-board.json export from that gate's
  red intake / investigation console, as ingested by POST /api/findings/ingest;
- ``baseline``       (optional) the F2 baseline status from the red repo,
  ``{"status": "clean"|"regressed", "violations": [...]}``;
- ``coverage``       (optional) a coverage figure AS REPORTED by that gate (the
  rollup never computes a coverage number itself — it cannot know the
  denominator, so an absent figure renders ABSENT, not zero);
- ``drilldown_url``  (optional, relative path only) per-gate drill-down link.

Absence is a first-class state (same discipline as the board's explicit
unknown badges): any per-gate number the artifact does not actually carry
renders as the literal string ``ABSENT`` — never ``0``, which would claim
evidence that does not exist.

Determinism: identical inputs give a byte-identical rollup. Gate rows are
sorted by ``gate_id`` and every mapping is serialised with sort_keys, so the
endpoint output is stable and hashable for comparison.

Fleet totals fold only over REPORTED numbers: a metric whose value is
ABSENT on every gate stays ABSENT fleet-wide, and the rollup lists which
gates were absent per metric so the fold is auditable rather than silent.
"""

from __future__ import annotations

import json
import pathlib
import re

ABSENT = "ABSENT"

GATE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

# A drill-down URL must stay a relative in-app path: artifacts are hostile
# content and an absolute/scheme href would be an injected external link.
_DRILLDOWN_RE = re.compile(r"^/[A-Za-z0-9._/~%-]*$")

# severities that count as violations in the board's risk lens taxonomy
# (same fold as RED_LENS_BY_SEVERITY "needs" lenses: high/critical).
VIOLATION_SEVERITIES = frozenset({"high", "critical"})
RED_DRIFT_PREFIX = "BEH-"

# per-finding verification states that count as unverified; a finding whose
# verification state is one of these is NOT proven yet.
UNVERIFIED_STATUSES = frozenset(
    {"pending", "unavailable", "unverified", "not_applicable", "unknown_key", "unsupported_schema"}
)

FLEET_SIDECAR = "fleet_gates.json"


def parse_artifacts(raw: object) -> list[dict]:
    """Accept a JSON array of gate artifacts or ``{"gates": [...]}``.

    Raises ValueError with a named message for anything invalid so the
    endpoint can return 422 without guessing.
    """
    if isinstance(raw, dict) and "gates" in raw:
        raw = raw["gates"]
    if not isinstance(raw, list):
        raise ValueError(
            'fleet artifacts must be a JSON array of gate artifacts'
            ' or {"gates": [...]}'
        )
    for a in raw:
        if not isinstance(a, dict):
            raise ValueError("each gate artifact must be a JSON object")
        if not isinstance(a.get("gate_id"), str) or not GATE_ID_RE.fullmatch(a["gate_id"]):
            raise ValueError("each gate artifact needs a gate_id of 1..128 gate-id characters")
        if "drilldown_url" in a and a["drilldown_url"] is not None:
            u = a["drilldown_url"]
            if not isinstance(u, str) or not _DRILLDOWN_RE.fullmatch(u):
                raise ValueError("drilldown_url must be a relative in-app path ('/...')")
    return raw


def _board_findings(board: object) -> list | None:
    """The findings list of a board export, or None when no board came."""
    if board is None:
        return None
    if isinstance(board, list):
        return board
    if isinstance(board, dict) and isinstance(board.get("findings"), list):
        return board["findings"]
    # a supplied board that does not carry a findings array is treated the
    # same as no board: absence, not an invented zero.
    return None


def _int_or_absent(value: object) -> object:
    """Pass a reported number through honestly (int or float); anything
    non-numeric is ABSENT."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return ABSENT
    return value


def gate_rollup(artifact: dict) -> dict:
    """Honest per-gate rollup of one artifact (pure, deterministic).

    Everything the artifact does not report renders ABSENT.
    """
    findings = _board_findings(artifact.get("board"))
    row: dict = {"gate_id": artifact["gate_id"]}
    if findings is None:
        row["violations"] = ABSENT
        row["drift"] = ABSENT
        row["unverified"] = ABSENT
        row["findings_total"] = ABSENT
    else:
        row["findings_total"] = len(findings)
        row["violations"] = sum(
            1
            for f in findings
            if isinstance(f, dict) and isinstance(f.get("severity"), str)
            and f["severity"] in VIOLATION_SEVERITIES
        )
        row["drift"] = sum(
            1
            for f in findings
            if isinstance(f, dict) and isinstance(f.get("rule"), str)
            and f["rule"].startswith(RED_DRIFT_PREFIX)
        )
        statuses = [
            f.get("verification_status")
            for f in findings
            if isinstance(f, dict) and isinstance(f.get("verification_status"), str)
        ]
        if statuses:
            row["unverified"] = sum(1 for s in statuses if s in UNVERIFIED_STATUSES)
        else:
            # findings present but none carries a verification status: the
            # gate gave no verification plane at all — ABSENT, not zero.
            row["unverified"] = ABSENT
    # coverage: reported honestly as given, never derived
    cov = artifact.get("coverage")
    if cov is None:
        row["coverage"] = ABSENT
    elif isinstance(cov, dict) and "reported" in cov:
        row["coverage"] = _int_or_absent(cov["reported"])
    else:
        row["coverage"] = _int_or_absent(cov)
    baseline = artifact.get("baseline")
    if baseline is None:
        row["baseline"] = ABSENT
        row["baseline_violations"] = ABSENT
    elif isinstance(baseline, dict):
        row["baseline"] = "clean" if baseline.get("status") == "clean" else "regressed"
        v = baseline.get("violations")
        row["baseline_violations"] = (
            len(v) if isinstance(v, list) else _int_or_absent(v)
        )
    else:
        row["baseline"] = ABSENT
        row["baseline_violations"] = ABSENT
    row["drilldown_url"] = (
        artifact.get("drilldown_url")
        if isinstance(artifact.get("drilldown_url"), str)
        else "/view/runs"
    )
    return row


def _fold(rows: list[dict], metric: str) -> dict:
    """Fold one per-gate metric fleet-wide; absent gates are named, not zeroed."""
    reported = {r["gate_id"]: r[metric] for r in rows if r[metric] != ABSENT}
    absent = [r["gate_id"] for r in rows if r[metric] == ABSENT]
    total: object = ABSENT
    if reported:
        total = sum(v for v in reported.values() if isinstance(v, int))
    out: dict[str, object] = {"absent_gates": sorted(absent)}
    if all(isinstance(v, int) for v in reported.values()):
        out["reported_total"] = total
    else:
        # non-int reported values (e.g. a bad coverage figure) surface as
        # ABSENT fleet-wide; the per-gate row still shows what came.
        out["reported_total"] = ABSENT
    return out


def fleet_rollup(artifacts: list[dict]) -> dict:
    """Deterministic fleet view over per-gate artifacts (pure).

    Gate rows sorted by gate_id; totals fold only over reported numbers and
    name the gates each fold could not see.
    """
    rows = sorted((gate_rollup(a) for a in artifacts), key=lambda r: r["gate_id"])
    return {
        "kind": "fleet_rollup",
        "gates": rows,
        "totals": {
            "gates": len(rows),
            "violations": _fold(rows, "violations"),
            "drift": _fold(rows, "drift"),
            "unverified": _fold(rows, "unverified"),
            "findings_total": _fold(rows, "findings_total"),
            "baseline_violations": _fold(rows, "baseline_violations"),
        },
        # coverage is per-gate AS REPORTED only; no fleet-wide figure is
        # ever invented (the rollup cannot know each gate's denominator).
        "coverage_note": (
            "coverage is shown per gate as reported by that gate; ABSENT "
            "means the gate supplied no coverage figure"
        ),
    }


# ------------------------------------------------------------- F2 baseline ----


def fleet_baseline(artifacts: list[dict]) -> dict:
    """Fleet-wide F2 baseline status: regression violations on ONE screen.

    Same absence discipline: a gate that sent no baseline shows ABSENT.
    Gate sections sorted by gate_id and violations kept verbatim in arrival
    order (deterministic for a fixed artifact array).
    """
    gates = []
    for a in sorted(artifacts, key=lambda x: x["gate_id"]):
        b = a.get("baseline")
        if isinstance(b, dict):
            gates.append(
                {
                    "gate_id": a["gate_id"],
                    "status": "clean" if b.get("status") == "clean" else "regressed",
                    "violations": (
                        b.get("violations")
                        if isinstance(b.get("violations"), list)
                        else ABSENT
                    ),
                }
            )
        else:
            gates.append({"gate_id": a["gate_id"], "status": ABSENT, "violations": ABSENT})
    regressed = [g["gate_id"] for g in gates if g["status"] == "regressed"]
    return {
        "kind": "fleet_baseline",
        "gates": gates,
        "regressed_gates": regressed,
    }


# ------------------------------------------------- sidecar persistence (UI) ---


def sidecar_path(base_dir: pathlib.Path) -> pathlib.Path:
    """Sidecar path resolved and confined to the data dir (same guard as
    triage_state.json — the data dir can come from the environment)."""
    base = pathlib.Path(base_dir).resolve()
    path = (base / FLEET_SIDECAR).resolve()
    if not path.is_relative_to(base):
        raise ValueError(
            f"fleet sidecar path {str(path)!s} escapes the demo data dir "
            f"{str(base)!s}; refusing to use it"
        )
    return path


def load_artifacts(data_dir: pathlib.Path) -> list[dict]:
    """Load persisted gate artifacts from the UI sidecar; none yet -> []."""
    p = sidecar_path(data_dir)
    try:
        raw = json.loads(p.read_text()) if p.is_file() else None
    except (OSError, ValueError):
        return []
    if not isinstance(raw, list):
        return []
    return [a for a in raw if isinstance(a, dict)]


def persist_artifacts(data_dir: pathlib.Path, artifacts: list[dict]) -> None:
    """Write gate artifacts to the sidecar (never the canonical store)."""
    p = sidecar_path(data_dir)
    p.write_text(json.dumps(artifacts, indent=2, sort_keys=True))
