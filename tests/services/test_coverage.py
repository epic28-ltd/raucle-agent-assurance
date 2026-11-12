# SPDX-License-Identifier: Apache-2.0
"""R1 coverage metric tests (raucle-free, offline, over the REAL pipeline).

Every fixture runs through the actual COR-01 correlation pipeline
(``reconcile`` — ADR-0002 states) via ``oaa_correlation.coverage``; numbers
below are asserted EXACTLY, never as ranges. Receipts are hand-built INDEX
rows (fake hashes, explicit ``synthetic`` marker) inside tests only.

Two determinism tests assert byte-identity of serialised output across
repeated invocations (same inputs -> byte-identical JSON) — the metric is
pure and reads no wall clock: the reconciliation moment is an argument.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parents[2] / "services" / "correlation" / "src")
)

import pytest

from oaa_correlation import (
    ReceiptRecord,
    TraceRecord,
    coverage,
    reconcile,
)

T0 = dt.datetime(2026, 11, 4, 12, 0, 0, tzinfo=dt.UTC)
PAST = T0 + dt.timedelta(seconds=60)  # grace (30s) elapsed for windows at T0


def hash(n: int) -> str:
    """Fake test-only digest — synthetic marker is asserted wherever used."""
    return f"sha256:{n:064d}"


def receipt(
    n: int, trace_id: str | None = "t1", decision: str = "allow", ets=None
) -> ReceiptRecord:
    return ReceiptRecord(
        receipt_hash=hash(n),
        trace_id=trace_id,
        decision=decision,
        event_time=ets or T0,
        provenance=f"synthetic-index-row-{n}",
        synthetic=True,
    )


def trace(
    trace_id: str = "t1",
    tool: str | None = "tool-0001",
    agent: str | None = None,
    start=None,
) -> TraceRecord:
    return TraceRecord(
        trace_id=trace_id,
        tool_invocation=tool,
        observed_at=start or T0,
        window_start=start or T0,
        window_end=(start or T0) + dt.timedelta(seconds=10),
        agent=agent,
    )


def states_by_trace(receipts, traces):
    """Which engine state each trace_id reconciles to (fixture sanity aid)."""
    result = reconcile(receipts, traces, at=PAST)
    return {r.trace_id: r.state for r in result.records if r.state != "trace_missing"}


# ------------------------------------------------------------------- numbers


def test_all_receipted_share_is_one() -> None:
    receipts = [receipt(1, "t1"), receipt(2, "t2"), receipt(3, "t3")]
    traces = [
        trace("t1", "shell", "agent-a"),
        trace("t2", "file_write", "agent-a"),
        trace("t3", "http_fetch", "agent-b"),
    ]
    assert states_by_trace(receipts, traces) == {"t1": "matched", "t2": "matched", "t3": "matched"}
    got = coverage(receipts, traces, at=PAST)
    assert got["schema_version"] == "oaa.coverage/v1"
    assert got["metric"] == "receipted_share"
    assert got["breakdown"] == {
        "total": 3,
        "receipted": 3,
        "out_of_gate": 0,
        "pending": 0,
    }
    assert got["receipted_share"] == 1.0
    assert got["states"] == {"matched": 3}
    # flags: nothing is flagged on a fully receipted plane
    assert got["flags"]["count"] == {
        "bypass_candidates": 0,
        "shadow_agents": 0,
        "uninstrumented_tools": 0,
    }
    assert got["flags"]["bypass_candidates"] == []
    assert got["flags"]["shadow_agents"] == []
    assert got["flags"]["uninstrumented_tools"] == []


def test_mixed_share_exact_fraction_and_rollups() -> None:
    receipts = [receipt(1, "t1"), receipt(2, "t2"), receipt(3, "t5")]
    traces = [
        trace("t1", "shell", "agent-a"),
        trace("t2", "file_write", "agent-a"),
        trace("t3", "shell", "agent-a"),  # no receipt -> out_of_gate
        trace("t4", "http_fetch", "agent-b"),  # no receipt -> out_of_gate
        trace("t5", "http_fetch", "agent-b"),
    ]
    assert states_by_trace(receipts, traces) == {
        "t1": "matched",
        "t2": "matched",
        "t3": "receipt_missing",
        "t4": "receipt_missing",
        "t5": "matched",
    }
    got = coverage(receipts, traces, at=PAST)
    # 3 of 5 observed actions carry a receipt — asserted exactly: 0.6
    assert got["breakdown"] == {
        "total": 5,
        "receipted": 3,
        "out_of_gate": 2,
        "pending": 0,
    }
    assert got["receipted_share"] == 0.6
    # per-tool rollup, exact:
    assert got["by_tool"] == {
        "file_write": {
            "total": 1,
            "receipted": 1,
            "out_of_gate": 0,
            "pending": 0,
            "receipted_share": 1.0,
        },
        "http_fetch": {
            "total": 2,
            "receipted": 1,
            "out_of_gate": 1,
            "pending": 0,
            "receipted_share": 0.5,
        },
        "shell": {
            "total": 2,
            "receipted": 1,
            "out_of_gate": 1,
            "pending": 0,
            "receipted_share": 0.5,
        },
    }
    # rollup buckets partition the plane: tool totals sum to the headline
    assert sum(r["total"] for r in got["by_tool"].values()) == got["breakdown"]["total"]
    assert sum(r["receipted"] for r in got["by_tool"].values()) == got["breakdown"]["receipted"]
    # same coherence for the per-agent rollup
    assert sum(r["total"] for r in got["by_agent"].values()) == got["breakdown"]["total"]
    assert got["by_agent"]["agent-b"]["receipted_share"] == 0.5
    assert got["by_agent"]["agent-a"]["receipted_share"] == 0.6667


def test_duplicate_late_and_ambiguous_still_receipted_with_state_map() -> None:
    late_receipt = receipt(2, "t-late", ets=T0 + dt.timedelta(seconds=300))
    receipts = [
        ReceiptRecord(
            receipt_hash=hash(10),
            trace_id="t-dup",
            decision="allow",
            event_time=T0,
            provenance="synthetic-delivery-a",
            synthetic=True,
        ),
        ReceiptRecord(
            receipt_hash=hash(10),
            trace_id="t-dup",
            decision="allow",
            event_time=T0,
            provenance="synthetic-delivery-b",
            synthetic=True,
        ),
        late_receipt,
        receipt(30, "t-amb"),
        receipt(31, "t-amb"),
    ]
    traces = [
        trace("t-dup", "file_write", "agent-a"),
        trace("t-late", "shell", "agent-a"),
        trace("t-amb", "http_fetch", "agent-a"),
    ]
    assert states_by_trace(receipts, traces) == {
        "t-dup": "duplicate",
        "t-late": "late_arrival",
        "t-amb": "ambiguous",
    }
    got = coverage(receipts, traces, at=PAST)
    # duplicate/late/ambiguous all carry a receipt -> receipted, share 1.0;
    # the state map keeps their caveats visible, never folded into "matched"
    assert got["breakdown"] == {
        "total": 3,
        "receipted": 3,
        "out_of_gate": 0,
        "pending": 0,
    }
    assert got["receipted_share"] == 1.0
    assert got["states"] == {"ambiguous": 1, "duplicate": 1, "late_arrival": 1}


def test_pending_is_disclosed_and_never_claims_an_out_of_gate() -> None:
    # receipt event 20s AFTER the reconciliation moment: the grace window is
    # still open, so the action is neither receipted nor out_of_gate.
    traces = [trace("t1", "shell", "agent-a")]
    receipts: list[ReceiptRecord] = []
    at = T0 + dt.timedelta(seconds=10)
    got = coverage(receipts, traces, at=at)
    assert got["breakdown"] == {
        "total": 1,
        "receipted": 0,
        "out_of_gate": 0,
        "pending": 1,
    }
    # interim share over an open plane is exactly zero-with-pending, which
    # the breakdown makes explicit; bucket partition invariant holds.
    assert got["receipted_share"] == 0.0
    assert got["states"] == {"pending": 1}
    # the same plane at a later moment (grace elapsed, no receipt) turns
    # terminal out_of_gate — absence past grace IS a result:
    got_later = coverage(receipts, traces, at=PAST)
    assert got_later["breakdown"] == {
        "total": 1,
        "receipted": 0,
        "out_of_gate": 1,
        "pending": 0,
    }
    assert got_later["states"] == {"receipt_missing": 1}


def test_trace_only_receipts_never_inflate_action_coverage() -> None:
    traces = [trace("t1", "shell", "agent-a")]
    receipts_no_stray = [receipt(1, "t1")]
    receipts_with_stray = [receipt(1, "t1"), receipt(9, "t-ghost")]  # ghost: no trace record
    got_plain = coverage(receipts_no_stray, traces, at=PAST)
    got_ghost = coverage(receipts_with_stray, traces, at=PAST)
    assert got_plain["breakdown"] == got_ghost["breakdown"]
    assert got_plain["receipted_share"] == got_ghost["receipted_share"] == 1.0
    # the ghost receipt-side state stays out of the action-plane state map
    assert got_ghost["states"] == {"matched": 1}


def test_shadow_agents_and_uninstrumented_tools_flagged() -> None:
    receipts = [receipt(1, "t-good"), receipt(2, "t-gated-1")]
    traces = [
        # agent-shadow: observed actions, zero receipts minted anywhere
        trace("t-shadow-1", "svc-ungated", "agent-shadow"),
        trace("t-shadow-2", "svc-ungated", "agent-shadow"),
        # partially covered agents/tools to keep the flags selective
        trace("t-good", "shell", "agent-clean"),
        trace("t-gated-1", "file_write", "agent-mixed"),
        trace("t-gated-2", "file_write", "agent-mixed"),  # no receipt
    ]
    assert states_by_trace(receipts, traces) == {
        "t-gated-2": "receipt_missing",
        "t-good": "matched",
        "t-gated-1": "matched",
        "t-shadow-1": "receipt_missing",
        "t-shadow-2": "receipt_missing",
    }
    got = coverage(receipts, traces, at=PAST)
    assert got["flags"]["count"] == {
        "bypass_candidates": 3,
        "shadow_agents": 1,
        "uninstrumented_tools": 1,
    }
    assert got["flags"]["shadow_agents"] == [
        {
            "name": "agent-shadow",
            "total": 2,
            "receipted": 0,
            "out_of_gate": 2,
            "pending": 0,
        }
    ]
    assert got["flags"]["uninstrumented_tools"] == [
        {
            "name": "svc-ungated",
            "total": 2,
            "receipted": 0,
            "out_of_gate": 2,
            "pending": 0,
        }
    ]
    # per-agent rollup still shows the shadow agent with share 0.0 — the
    # flag cites the same numbers (one source, no disagreement possible)
    assert got["by_agent"]["agent-shadow"]["receipted_share"] == 0.0
    assert got["by_tool"]["svc-ungated"]["receipted_share"] == 0.0
    # partially-covered tool (1 of 2 receipted) is NOT flagged uninstrumented
    assert got["by_tool"]["file_write"]["receipted"] == 1
    assert all(r["name"] != "file_write" for r in got["flags"]["uninstrumented_tools"])


def test_bypass_candidates_list_out_of_gate_rows_exactly() -> None:
    receipts = [receipt(1, "t-ok")]
    traces = [
        trace("t-ok", "shell", "agent-a"),
        trace("t-gap-b", "shell", "agent-b"),  # out_of_gate
        trace("t-gap-a", "file_write", "agent-c"),  # out_of_gate
    ]
    got = coverage(receipts, traces, at=PAST)
    assert [c["trace_id"] for c in got["flags"]["bypass_candidates"]] == [
        "t-gap-a",
        "t-gap-b",
    ]  # sorted by trace_id, deterministic
    for cand in got["flags"]["bypass_candidates"]:
        assert cand["state"] == "receipt_missing"
        assert cand["evidence_class"] == "trace_plane_only"
        assert "tool-side" in cand["note"]  # ADR-0004: never a confirmed bypass
    assert got["flags"]["count"]["bypass_candidates"] == 2


def test_multi_row_trace_applies_state_per_record() -> None:
    receipts = [receipt(1, "t1")]
    traces = [
        trace("t1", "shell", "agent-a"),
        trace("t1", "http_fetch", "agent-a"),
    ]
    got = coverage(receipts, traces, at=PAST)
    assert got["breakdown"] == {
        "total": 2,
        "receipted": 2,
        "out_of_gate": 0,
        "pending": 0,
    }
    assert got["states"] == {"matched": 2}
    assert got["by_tool"]["shell"]["total"] == 1
    assert got["by_tool"]["http_fetch"]["total"] == 1


def test_unattributed_tool_and_agent_get_explicit_unknown_labels() -> None:
    receipts = [receipt(1, "t1")]
    traces = [trace("t1", tool=None, agent=None)]
    got = coverage(receipts, traces, at=PAST)
    assert got["breakdown"]["total"] == 1
    # explicit-unknown labels: "not recorded" is never folded away silently
    assert got["by_tool"] == {
        "(tool not recorded)": {
            "total": 1,
            "receipted": 1,
            "out_of_gate": 0,
            "pending": 0,
            "receipted_share": 1.0,
        }
    }
    assert got["by_agent"] == {
        "(agent not recorded)": {
            "total": 1,
            "receipted": 1,
            "out_of_gate": 0,
            "pending": 0,
            "receipted_share": 1.0,
        }
    }
    # unknown-attribution actions are never treated as shadow agents
    assert got["flags"]["shadow_agents"] == []


def test_empty_plane_share_is_none_not_zero() -> None:
    got = coverage([], [], at=PAST)
    assert got["breakdown"] == {"total": 0, "receipted": 0, "out_of_gate": 0, "pending": 0}
    assert got["receipted_share"] is None
    assert got["by_tool"] == {}
    assert got["by_agent"] == {}
    assert got["states"] == {}
    assert got["flags"]["count"] == {
        "bypass_candidates": 0,
        "shadow_agents": 0,
        "uninstrumented_tools": 0,
    }


# ---------------------------------------------------------------- determinism


def test_deterministic_byte_identical_output() -> None:
    receipts = [receipt(1, "t1"), receipt(2, "t3")]
    traces = [
        trace("t1", "shell", "agent-a"),
        trace("t2", "shell", "agent-b"),  # out_of_gate
        trace("t3", "file_write", "agent-a"),
    ]
    one = json.dumps(coverage(receipts, traces, at=PAST), sort_keys=True)
    two = json.dumps(coverage(receipts, traces, at=PAST), sort_keys=True)
    assert one == two


def test_determinism_holds_for_shuffled_input_order() -> None:
    """Row order in must not change the rendered numbers or flag order."""
    receipts = [receipt(1, "t2"), receipt(2, "t1")]
    traces = [
        trace("t1", "shell", "agent-b"),
        trace("t2", "shell", "agent-a"),
        trace("t3", "file_write", "agent-a"),
    ]
    forward = json.dumps(coverage(receipts, traces, at=PAST), sort_keys=True)
    backward = json.dumps(
        coverage(list(reversed(receipts)), list(reversed(traces)), at=PAST),
        sort_keys=True,
    )
    # the numbers are identical; only dict insertion order may differ, which
    # sort_keys erases — byte-identical means the metric is order-stable.
    assert forward == backward


@pytest.mark.parametrize(("receipted", "total"), [(0, 5), (1, 6), (2, 7), (5, 8), (7, 8)])
def test_share_rounds_to_four_places(receipted: int, total: int) -> None:
    receipts = [receipt(1 + n, f"t{1 + n}") for n in range(receipted)]
    traces = [trace(f"t{1 + n}", "shell", "agent-a") for n in range(total)]
    got = coverage(receipts, traces, at=PAST)
    assert got["breakdown"] == {
        "total": total,
        "receipted": receipted,
        "out_of_gate": total - receipted,
        "pending": 0,
    }
    assert got["receipted_share"] == round(receipted / total, 4)
