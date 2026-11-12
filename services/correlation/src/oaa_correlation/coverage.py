"""Open Agent Assurance — receipted-share coverage metric over COR-01 (ADR-0002).

``coverage()`` computes ONE number on top of the correlation engine's own
reconciliation states — the receipted share:

    receipted_share = receipted / total

where the unit of account is an **observed agent action**: one ADR-0002
trace-side record (``TraceRecord``) fed to ``reconcile()``. A receipt
represents a record when the engine's terminal state for that record's
trace_id carries a correlated receipt (``matched``, ``duplicate``,
``late_arrival``, ``ambiguous`` — in every one of those states at least
one receipt resolved to the record). A record whose receipt never arrived
past the grace window (``receipt_missing``) is the **out_of_gate** bucket:
the action was observed and left no gate evidence.

Bucket discipline (companion invariants):

- ``total = receipted + out_of_gate + pending`` always holds; ``pending``
  (grace-open, ADR-0002) is disclosed, never folded into either bucket —
  absence inside the grace window is never a result.
- Receipts whose trace_id has no observed record (``trace_missing``) are
  receipt-side states: they never inflate the action coverage number.
- Trace-plane absence is never a bypass signal (ADR-0004): unpaired
  observed actions surface as ``bypass_candidates`` — candidates only,
  whose confirmation requires a tool-side or custody vantage point the
  agent does not control.

Shadow agents: an agent attributed to observed actions
(``TraceRecord.agent``) who minted zero receipts correlated to any of
them. Uninstrumented tools: a tool observed acting
(``TraceRecord.tool_invocation``) for which no receipt was correlated
anywhere in the observed window — custody coverage for that tool is zero
on the trace plane and must be verified with a tool-side vantage before
any claim (ADR-0004 §3).

Determinism: ``coverage()`` is a pure function of its inputs with an
explicit reconciliation moment (pass ``at=None`` for "as if every window
had closed", the engine's documented semantics). The output map is sorted
and two runs on the same inputs serialize byte-identically (asserted in
tests). No synthetic data is introduced: every listed flag cites the
engine records it was derived from.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import datetime as dt

from .core import (
    CorrelationConfig,
    ReceiptRecord,
    TraceRecord,
    reconcile,
)

SCHEMA_VERSION = "oaa.coverage/v1"
_METRIC = "receipted_share"

_NO_TOOL = "(tool not recorded)"
_NO_AGENT = "(agent not recorded)"

# Engine states that count an action as receipted: at least one receipt
# resolved to the trace side. ``duplicate`` collapses deliveries of ONE
# receipt; ``late_arrival`` and ``ambiguous`` carry receipts with
# correlation caveats the state map exposes alongside the count.
RECEIPTED_STATES = frozenset({"matched", "duplicate", "late_arrival", "ambiguous"})
OUT_OF_GATE_STATES = frozenset({"receipt_missing"})

_ROLLUP_KEYS = ("total", "receipted", "out_of_gate", "pending")


def _new_rollup() -> dict:
    return {"total": 0, "receipted": 0, "out_of_gate": 0, "pending": 0}


def _trace_states(rows_by_trace: dict[str, list[TraceRecord]], result) -> dict[str, str]:
    """Terminal state per observed trace_id.

    Derived from the engine's own output: a trace_id with observed records
    and no terminal correlation record reconciles to ``pending`` (grace
    open). Receipt-side-only ``trace_missing`` records name trace_ids with
    no observed record and never enter this map.
    """
    states: dict[str, str] = {}
    for rec in result.records:
        if rec.trace_id is not None and rec.trace_id in rows_by_trace:
            states[rec.trace_id] = rec.state
    return states


def _rollup_bucket(rollups: dict[str, dict], key: str | None, unknown_label: str) -> dict:
    """Rollup bucket for ``key`` (None folds to an explicit-unknown label)."""
    name = key if key is not None else unknown_label
    if name not in rollups:
        rollups[name] = _new_rollup()
    return rollups[name]


def _fold(rollup: dict, bucket: str, count: int) -> None:
    rollup["total"] += count
    rollup[bucket] += count


def _flag_row(name: str, rollup: dict) -> dict:
    """Honest flag row: what the flag is named by and its rollup evidence."""
    row = {"name": name}
    row.update({k: rollup[k] for k in _ROLLUP_KEYS})
    return row


def _share(total: int, receipted: int) -> float | None:
    """The receipted share, None at zero observations (never a fake 0.0)."""
    return None if total == 0 else round(receipted / total, 4)


def _receipted_share(rollups: dict[str, dict]) -> None:
    """Attach receipted_share to every rollup bucket in place."""
    for rollup in rollups.values():
        rollup["receipted_share"] = _share(rollup["total"], rollup["receipted"])


def _flag_rows(rollups: dict[str, dict]) -> list[dict]:
    """Rollups with observed actions and zero correlated receipts, in name order."""
    return [
        _flag_row(name, rollup)
        for name, rollup in sorted(rollups.items())
        if rollup["total"] > 0 and rollup["receipted"] == 0
    ]


def _bucket_for(state: str) -> str:
    """Partition an engine state into receipted / out_of_gate / pending."""
    if state in RECEIPTED_STATES:
        return "receipted"
    if state in OUT_OF_GATE_STATES:
        return "out_of_gate"
    return "pending"


def _accumulate_buckets(
    rows_by_trace: dict[str, list[TraceRecord]],
    states: dict[str, str],
    total: int,
) -> tuple[dict, dict[str, dict], dict[str, dict], dict[str, int]]:
    """Breakdown counts, per-tool / per-agent rollups and per-state counts."""
    breakdown = {"total": total, "receipted": 0, "out_of_gate": 0, "pending": 0}
    by_tool: dict[str, dict] = {}
    by_agent: dict[str, dict] = {}
    state_counts: dict[str, int] = {}
    for trace_id in sorted(rows_by_trace):
        rows = rows_by_trace[trace_id]
        state = states.get(trace_id, "pending")
        state_counts[state] = state_counts.get(state, 0) + len(rows)
        bucket = _bucket_for(state)
        breakdown[bucket] += len(rows)
        for tr in rows:
            _fold(_rollup_bucket(by_tool, tr.tool_invocation, _NO_TOOL), bucket, 1)
            _fold(_rollup_bucket(by_agent, tr.agent, _NO_AGENT), bucket, 1)
    return breakdown, by_tool, by_agent, state_counts


def _bypass_candidates(traces: list[TraceRecord], states: dict[str, str]) -> list[dict]:
    """Observed actions beyond grace with no gate receipt (ADR-0004 candidates)."""
    candidates: list[dict] = []
    for tr in sorted(traces, key=lambda t: (t.trace_id, t.tool_invocation or "", t.agent or "")):
        if states.get(tr.trace_id) in OUT_OF_GATE_STATES:
            candidates.append(
                {
                    "trace_id": tr.trace_id,
                    "tool": tr.tool_invocation if tr.tool_invocation is not None else _NO_TOOL,
                    "agent": tr.agent if tr.agent is not None else _NO_AGENT,
                    "state": "receipt_missing",
                    "evidence_class": "trace_plane_only",
                    "note": (
                        "observed action with no gate receipt beyond grace "
                        "(ADR-0004: candidate only; confirmation needs a "
                        "tool-side or custody vantage)"
                    ),
                }
            )
    return candidates


def coverage(
    receipts: list[ReceiptRecord],
    traces: list[TraceRecord],
    *,
    config: CorrelationConfig | None = None,
    at: dt.datetime | None = None,
) -> dict:
    """Receipted-share coverage over the correlation engine's states.

    Args:
        receipts: receipt INDEX rows for the org, exactly as fed to
            ``reconcile()`` — index fields only, never canonical bytes.
        traces: observed agent actions — ADR-0002 trace-side records with
            optional tool / agent attribution (``tool_invocation`` /
            ``agent``).
        config: correlation knobs (the grace window); defaults apply.
        at: reconciliation moment; ``None`` reconciles as if every window
            had closed (the engine's documented semantics) so the output is
            deterministic without a wall clock.

    Returns a JSON-ready dict; every number is derived from the engine's
    own ``reconcile()`` output — no synthetic or defaulted values.
    """
    result = reconcile(receipts, traces, config=config or CorrelationConfig(), at=at)

    rows_by_trace: dict[str, list[TraceRecord]] = {}
    for tr in traces:
        rows_by_trace.setdefault(tr.trace_id, []).append(tr)

    states = _trace_states(rows_by_trace, result)

    breakdown, by_tool, by_agent, state_counts = _accumulate_buckets(
        rows_by_trace, states, len(traces)
    )

    bypass_candidates = _bypass_candidates(traces, states)

    # Flags derive from the frozen rollups, so a flag can never contradict
    # the per-tool / per-agent buckets it was computed from.
    shadow_agents = _flag_rows(by_agent)
    uninstrumented_tools = _flag_rows(by_tool)
    for rollups in (by_tool, by_agent):
        _receipted_share(rollups)

    assert breakdown["total"] == (
        breakdown["receipted"] + breakdown["out_of_gate"] + breakdown["pending"]
    )  # buckets partition the observed-action plane

    return {
        "schema_version": SCHEMA_VERSION,
        "metric": _METRIC,
        "receipted_share": _share(breakdown["total"], breakdown["receipted"]),
        "breakdown": breakdown,
        "flags": {
            "count": {
                "bypass_candidates": len(bypass_candidates),
                "shadow_agents": len(shadow_agents),
                "uninstrumented_tools": len(uninstrumented_tools),
            },
            "bypass_candidates": bypass_candidates,
            "shadow_agents": shadow_agents,
            "uninstrumented_tools": uninstrumented_tools,
        },
        "by_tool": dict(sorted(by_tool.items())),
        "by_agent": dict(sorted(by_agent.items())),
        "states": dict(sorted(state_counts.items())),
    }
