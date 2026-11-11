"""UI-05 coherence pass: shared counting module unit tests.

The counting module is the ONE source of every number both surfaces render.
These tests pin the reconciliation arithmetic: buckets partition their
totals, findings open + closed + suppressed == total, and the board KPIs /
columns / chip members all equal the same module's output. One test proves
the cross-surface contract: the console's overview trust block equals this
module's output.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import pathlib
import sys

UI = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(UI / "src"))
for _src in (
    UI.parents[1] / "packages" / "raucle-adapter" / "src",
    UI.parents[1] / "services" / "correlation" / "src",
    UI.parents[1] / "services" / "rules" / "src",
):
    sys.path.insert(0, str(_src))

from oaa_investigation_ui.counting import (  # noqa: E402
    BOARD_STATES,
    CORRELATION_STATES,
    LENS_BY_RULE,
    VERIFICATION_BUCKETS,
    count_evidence,
    default_board_state,
    finding_lens,
)
from oaa_investigation_ui.data import DemoData  # noqa: E402

DATA_DIR = UI / "demo_data"


def test_counting_module_structure():
    counts = count_evidence(DATA_DIR, at="2026-01-01T00:00:00+00:00")
    assert counts["schema_version"] == 1
    assert counts["at"] == "2026-01-01T00:00:00+00:00"
    for key in ("verification", "correlation", "health", "findings", "triaged_findings", "runs"):
        assert key in counts, key
    assert sorted(counts["verification"]["buckets"]) == sorted(VERIFICATION_BUCKETS)
    assert sorted(counts["correlation"]["states"]) == sorted(CORRELATION_STATES)


def test_verification_buckets_partition_the_plane():
    counts = count_evidence(DATA_DIR)
    v = counts["verification"]
    assert sum(v["states"].values()) == v["total"]
    assert sum(v["buckets"].values()) == v["total"]
    assert v["buckets"]["unproven"] == v["states"].get("unknown_key", 0) + v["states"].get(
        "pending", 0
    )
    assert v["buckets"]["unaccounted"] == v["states"].get("unsupported_schema", 0) + v[
        "states"
    ].get("invalid", 0)
    assert v["buckets"]["exempt"] == v["states"].get("unavailable", 0) + v["states"].get(
        "not_applicable", 0
    )


def test_correlation_states_materialised_with_zeros():
    counts = count_evidence(DATA_DIR)
    states = counts["correlation"]["states"]
    assert sum(states.values()) == counts["verification"]["total"]
    assert all(s in states for s in CORRELATION_STATES)
    assert states["matched_degraded"] >= 1
    assert states["trace_missing"] >= 1


def test_findings_reconcile_open_closed_suppressed():
    counts = count_evidence(DATA_DIR)
    lens = counts["findings"]["lens"]
    assert lens["needs_investigation"] + lens["unproven"] + lens["coverage_gaps"] == lens["open"]
    assert lens["open"] + lens["closed"] + lens["suppressed"] == counts["findings"]["total"]
    assert counts["findings"]["total"] == counts["triaged_findings"]["total"]


def test_lens_mapping_is_total_over_rules():
    assert set(LENS_BY_RULE) == {f"SEC-{i:03d}" for i in range(1, 12)}
    assert set(LENS_BY_RULE.values()) == {"needs", "unproven", "gaps"}


def test_board_states_single_taxonomy():
    assert BOARD_STATES == ("new", "investigating", "suppressed", "closed")


def test_default_board_state_and_lens():
    assert default_board_state({"suppressed": True}) == "suppressed"
    assert default_board_state({"suppressed": False}) == "new"
    assert finding_lens({"rule_id": "SEC-001"}) == "gaps"
    assert finding_lens({"rule_id": "SEC-009"}) == "needs"
    assert finding_lens({"rule_id": "SEC-999"}) == "unproven"


def test_counts_with_reused_demo_data():
    """Passing an already-loaded DemoData must give the same numbers."""
    data = DemoData(DATA_DIR)
    a = count_evidence(DATA_DIR, data=data)
    b = count_evidence(DATA_DIR)
    assert a["verification"] == b["verification"]
    assert a["findings"] == b["findings"]


def test_cross_surface_console_overview_matches_counts(monkeypatch):
    """The console's server-side figures (its overview trust block) read the
    same counting module output, so the surfaces can never drift."""
    console_src = UI.parents[1] / "services" / "console" / "src"
    monkeypatch.syspath_prepend(str(console_src))
    from fastapi.testclient import TestClient  # noqa: PLC0415
    from raucle_console.app import create_app  # noqa: PLC0415

    overview = TestClient(create_app()).get("/api/overview").json()
    counts = count_evidence(DATA_DIR)
    assert overview["trust"]["receipts_minted"] == counts["trust"]["receipts_minted"]
    assert overview["trust"]["receipts_verified"] == counts["trust"]["verification_rows"]
    assert overview["trust"]["receipts_valid"] == counts["trust"]["verification_valid"]
    assert overview["trust"]["spans_indexed"] == counts["verification"]["total"]
    assert overview["trust"]["verification_distribution"] == counts["verification"]["states"]
    assert overview["trust"]["verification_buckets"] == counts["verification"]["buckets"]
    assert overview["trust"]["findings"] == counts["findings"]
