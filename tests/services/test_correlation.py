# SPDX-License-Identifier: Apache-2.0
"""COR-01 correlation engine tests (raucle-free, offline, table-driven).

Everything here is synthetic: receipts are hand-built INDEX ROWS with fake
hashes and an explicit ``synthetic: true`` marker — never canonical evidence
store fixtures. The evidence-store immutability invariant is asserted with a
read-only mode check (sha256 before/after).
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import pathlib
import sys

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parents[2] / "services" / "correlation" / "src")
)

import pytest

from oaa_correlation import (
    CORRELATION_STATES,
    CorrelationConfig,
    CorrelationRecord,
    ReceiptRecord,
    TraceRecord,
    load_receipt_index,
    reconcile,
)

T0 = dt.datetime(2026, 11, 4, 12, 0, 0, tzinfo=dt.UTC)


def hash(n: int) -> str:
    """Fake test-only digest — synthetic marker is asserted wherever used."""
    return f"sha256:{n:064d}"


def receipt(n: int, trace_id: str | None = "t1", decision: str = "allow", ets=None, prov=None):
    return ReceiptRecord(
        receipt_hash=hash(n),
        trace_id=trace_id,
        decision=decision,
        event_time=ets or T0,
        provenance=prov or f"synthetic-index-row-{n}",
        synthetic=True,
    )


def trace(trace_id: str = "t1", observed=None, start=None, end=None):
    return TraceRecord(
        trace_id=trace_id,
        tool_invocation="tool-0001",
        observed_at=observed or T0,
        window_start=start,
        window_end=end,
    )


CASES = [
    # (name, receipts, traces, at, expected_state per trace_id)
    ("matched", [receipt(1)], [trace()], T0 + dt.timedelta(seconds=60), "matched"),
    (
        "duplicate",
        [receipt(1, prov="delivery-a"), receipt(1, prov="delivery-b")],
        [trace()],
        T0 + dt.timedelta(seconds=60),
        "duplicate",
    ),
    ("ambiguous", [receipt(1), receipt(2)], [trace()], T0 + dt.timedelta(seconds=60), "ambiguous"),
    (
        "late_arrival",
        [receipt(1, ets=T0 + dt.timedelta(seconds=120))],
        [trace()],
        T0 + dt.timedelta(seconds=180),
        "late_arrival",
    ),
    ("receipt_missing", [], [trace()], T0 + dt.timedelta(seconds=60), "receipt_missing"),
    ("trace_missing", [receipt(3)], [], T0 + dt.timedelta(seconds=60), "trace_missing"),
    # out-of-order receipt: event 20s before window start, inside the 30s grace
    (
        "out_of_order_in_grace",
        [receipt(4, ets=T0 - dt.timedelta(seconds=20))],
        [trace()],
        T0 + dt.timedelta(seconds=60),
        "matched",
    ),
    # out-of-order receipt: event far before the window, beyond grace
    (
        "out_of_order_beyond_grace",
        [receipt(5, ets=T0 - dt.timedelta(seconds=300))],
        [trace()],
        T0 + dt.timedelta(seconds=360),
        "late_arrival",
    ),
]


def test_states_table_driven():
    for name, recs, trs, at, expected in CASES:
        result = reconcile(recs, trs, CorrelationConfig(), at=at)
        states = [r.state for r in result.records]
        assert states == [expected], f"{name}: got {states}, expected [{expected!r}]"
        assert result.pending == 0, name
        rec = result.records[0]
        assert rec.trace_id == "t1", name
        if recs:
            assert all(rec.receipt_hashes), name


def test_grace_open_records_are_pending_not_missing():
    # trace observed 5s ago with default 30s grace: no receipt yet, still open
    result = reconcile(
        [], [trace()], CorrelationConfig(grace_seconds=30), at=T0 + dt.timedelta(seconds=5)
    )
    assert result.records == []
    assert result.pending == 1
    # same, past grace -> receipt_missing (absence becomes a reportable gap)
    result = reconcile(
        [], [trace()], CorrelationConfig(grace_seconds=30), at=T0 + dt.timedelta(seconds=60)
    )
    assert [r.state for r in result.records] == ["receipt_missing"]
    # mirrored: receipt with no trace, still open
    result = reconcile(
        [receipt(6)], [], CorrelationConfig(grace_seconds=30), at=T0 + dt.timedelta(seconds=5)
    )
    assert result.records == []
    assert result.pending == 1


def test_duplicate_collapses_provenance_not_data():
    a = receipt(1, prov="delivery-a")
    b = receipt(1, prov="delivery-b")
    result = reconcile([a, b, b], [trace()], at=T0 + dt.timedelta(seconds=60))
    rec = result.records[0]
    assert rec.state == "duplicate"
    assert len(rec.provenance) == 3  # every delivery's provenance preserved
    assert sorted(rec.provenance) == ["delivery-a", "delivery-b", "delivery-b"]
    assert rec.receipt_hashes == (hash(1),)
    # distinct hashes never collapse to duplicate — they are ambiguous
    result = reconcile([a, receipt(9)], [trace()], at=T0 + dt.timedelta(seconds=60))
    assert result.records[0].state == "ambiguous"
    assert len(result.records[0].receipt_hashes) == 2


def test_no_trace_id_receipt_missing_trace():
    orphan = receipt(7, trace_id=None)
    result = reconcile([orphan], [trace()], at=T0 + dt.timedelta(seconds=60))
    rec = result.records[0]
    assert rec.state == "trace_missing"
    assert rec.trace_id is None
    assert rec.notes  # absence is explained, never silently dropped


def test_receipt_without_trace_id_pending_within_grace():
    orphan = receipt(7, trace_id=None)
    result = reconcile([orphan], [trace()], at=T0 + dt.timedelta(seconds=5))
    # orphan receipt AND the trace side of t1 are both still open within grace
    assert result.records == []
    assert result.pending == 2


def test_state_enum_matches_adr_0002():
    assert CORRELATION_STATES == (
        "matched",
        "duplicate",
        "ambiguous",
        "late_arrival",
        "receipt_missing",
        "trace_missing",
    )


def test_unknown_state_rejected_on_record():
    good = CorrelationRecord(state="matched", trace_id="t1")
    with pytest.raises(ValueError, match="unknown correlation state"):
        dataclasses.replace(good, state="matched-and-fine")


def test_read_only_index_load_is_sha256_immutable(tmp_path: pathlib.Path):
    # Synthetic index rows only — fake hashes, explicit synthetic marker.
    rows = [
        {
            "receipt_hash": hash(1),
            "trace_id": "t1",
            "decision": "allow",
            "event_time": T0.isoformat(),
            "provenance": "synthetic-1",
            "synthetic": True,
        },
        {
            "receipt_hash": hash(2),
            "trace_id": "t1",
            "decision": "deny",
            "event_time": T0.isoformat(),
            "provenance": "synthetic-2",
            "synthetic": True,
        },
    ]
    path = tmp_path / "receipt-index.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    records, digest = load_receipt_index(path, read_only=True)
    _again, digest2 = load_receipt_index(path, read_only=True)
    assert [r.synthetic for r in records] == [True, True]
    assert digest == digest2  # sha256-immutability across read-only loads

    # reconcile straight off the loaded index
    result = reconcile(records, [trace()], at=T0 + dt.timedelta(seconds=60))
    assert [r.state for r in result.records] == ["ambiguous"]


def test_load_receipt_index_rejects_missing_hash(tmp_path: pathlib.Path):
    path = tmp_path / "bad.jsonl"
    path.write_text(
        json.dumps({"receipt_hash": "", "event_time": T0.isoformat()}) + "\n", encoding="utf-8"
    )
    try:
        load_receipt_index(path)
    except ValueError as exc:
        assert "receipt_hash" in str(exc)
    else:
        raise AssertionError("empty digest must be rejected")


# ---------------------------------------------------------------- ADR-0005
def test_gate_id_required_for_evidence_backed_rows():
    """ADR-0005: many-gate deployments must be attributable to a gate."""
    with pytest.raises(ValueError, match="gate_id is required"):
        ReceiptRecord(
            receipt_hash="a" * 64,
            trace_id="t1",
            decision="allow",
            event_time=dt.datetime.now(dt.UTC),
        )
    # synthetic rows may omit it
    r = ReceiptRecord(
        receipt_hash="b" * 64,
        trace_id="t2",
        decision="deny",
        event_time=dt.datetime.now(dt.UTC),
        synthetic=True,
    )
    assert r.gate_id is None
