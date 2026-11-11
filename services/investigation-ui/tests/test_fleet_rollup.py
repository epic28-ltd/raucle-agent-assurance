"""Fleet rollup (EPIC P2.C) unit tests: determinism and honest ABSENT handling.

The rollup is a reporting surface, not a truth source: it must render ABSENT
for any figure a gate artifact did not actually carry (never a fabricated
zero), fold totals only over reported numbers, and never invent a fleet-wide
coverage figure.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import pathlib
import sys

import pytest

UI = pathlib.Path(__file__).resolve().parents[1]
REPO_ROOT = UI.parents[1]
sys.path.insert(0, str(UI / "src"))

from oaa_investigation_ui.fleet_rollup import (  # noqa: E402
    ABSENT,
    fleet_baseline,
    fleet_rollup,
    gate_rollup,
    parse_artifacts,
)

BOARD = {
    "kind": "findings_board",
    "findings": [
        {"id": "a", "rule": "RED-003", "severity": "critical", "verification_status": "pending"},
        {"id": "b", "rule": "RED-006", "severity": "low", "verification_status": "valid"},
        {"id": "c", "rule": "BEH-A", "severity": "medium"},
    ],
}


def test_full_artifact_counts_every_plane() -> None:
    row = gate_rollup(
        {
            "gate_id": "gate-b",
            "board": BOARD,
            "coverage": {"reported": 87.5},
            "baseline": {"status": "regressed", "violations": [{"rule": "F2-x"}]},
            "drilldown_url": "/view/runs",
        }
    )
    assert row == {
        "gate_id": "gate-b",
        "findings_total": 3,
        "violations": 1,  # critical only (board risk lens: high/critical)
        "drift": 1,  # BEH- rule
        "unverified": 1,  # pending status
        "coverage": 87.5,  # AS REPORTED, honestly
        "baseline": "regressed",
        "baseline_violations": 1,
        "drilldown_url": "/view/runs",
    }


def test_without_optional_figures_everything_is_absent_not_zero() -> None:
    row = gate_rollup({"gate_id": "gate-a"})
    assert row["violations"] == ABSENT
    assert row["drift"] == ABSENT
    assert row["unverified"] == ABSENT
    assert row["findings_total"] == ABSENT
    assert row["coverage"] == ABSENT
    assert row["baseline"] == ABSENT
    assert row["baseline_violations"] == ABSENT
    assert 0 not in row.values()


def test_board_without_findings_list_is_absent_not_zero() -> None:
    """A board export that carries no findings array is absence of evidence,
    so the counts stay ABSENT rather than claiming an empty board."""
    row = gate_rollup({"gate_id": "g", "board": {"kind": "findings_board", "kpis": {}}})
    assert row["violations"] == ABSENT
    assert row["findings_total"] == ABSENT


def test_findings_without_verification_status_leave_unverified_absent() -> None:
    row = gate_rollup({"gate_id": "g", "board": {"findings": [{"id": "x", "severity": "low"}]}})
    assert row["violations"] == 0  # a real, evidenced zero
    assert row["unverified"] == ABSENT  # no verification plane came at all


def test_bad_coverages_are_absent_not_clamped() -> None:
    assert gate_rollup({"gate_id": "g", "coverage": "97%"})["coverage"] == ABSENT
    assert gate_rollup({"gate_id": "g", "coverage": {"reported": "n/a"}})["coverage"] == ABSENT
    assert gate_rollup({"gate_id": "g", "coverage": 97})["coverage"] == 97


def test_rollup_is_deterministic_and_sorted_by_gate_id() -> None:
    artifacts = [
        {"gate_id": "gate-b", "board": BOARD, "coverage": 50},
        {"gate_id": "gate-a", "board": BOARD},
        {"gate_id": "gate-c"},
    ]
    first = fleet_rollup(artifacts)
    again = fleet_rollup(list(reversed(artifacts)))
    assert first == again
    assert json.dumps(first, sort_keys=True) == json.dumps(again, sort_keys=True)
    assert [g["gate_id"] for g in first["gates"]] == ["gate-a", "gate-b", "gate-c"]


def test_totals_fold_only_reported_and_name_absent_gates() -> None:
    view = fleet_rollup(
        [
            {"gate_id": "gate-a", "board": BOARD, "coverage": 50},
            {"gate_id": "gate-b"},
        ]
    )
    totals = view["totals"]
    assert totals["violations"]["reported_total"] == 1
    assert totals["violations"]["absent_gates"] == ["gate-b"]
    assert totals["drift"]["reported_total"] == 1
    assert totals["drift"]["absent_gates"] == ["gate-b"]
    assert totals["unverified"]["reported_total"] == 1
    # a metric absent everywhere is ABSENT fleet-wide, never 0
    assert totals["baseline_violations"]["reported_total"] == ABSENT
    assert totals["baseline_violations"]["absent_gates"] == ["gate-a", "gate-b"]


def test_baseline_surface_absent_and_regressed_gates() -> None:
    view = fleet_baseline(
        [
            {"gate_id": "b"},
            {"gate_id": "a", "baseline": {"status": "clean", "violations": []}},
            {"gate_id": "c", "baseline": {"status": "regressed", "violations": [{"v": 1}]}},
        ]
    )
    assert view["regressed_gates"] == ["c"]
    assert [g["gate_id"] for g in view["gates"]] == ["a", "b", "c"]
    assert view["gates"][1]["status"] == ABSENT
    assert view["gates"][2]["violations"] == [{"v": 1}]


def test_artifact_parser_validation() -> None:
    assert parse_artifacts({"gates": [{"gate_id": "ok"}]}) == [{"gate_id": "ok"}]

    for bad in ([{"gate_id": "../x"}], [{"gate_id": 5}], ["nope"], {}, None):
        with pytest.raises(ValueError):
            parse_artifacts(bad)
    with pytest.raises(ValueError, match="relative in-app path"):
        parse_artifacts([{"gate_id": "ok", "drilldown_url": "https://evil.example"}])
