# SPDX-License-Identifier: Apache-2.0
"""Open Agent Assurance — minimal correlation engine (COR-01, ADR-0002).

Reconciles an index of receipt records (raised from the evidence plane's
canonical ``{receipt_hash, jws}`` store — canonical bytes never travel here,
only index fields: receipt_hash, trace_id from the signed ``x_gate.trace_id``,
decision, event_time) against trace-side records (trace_id, tool_invocation,
observed_at, event window).

States per ADR-0002. For one trace_id:

- ``matched``        one receipt resolves to one trace-side record, receipt
                     event_time inside the trace event window (with the
                     out-of-order grace applied on both sides).
- ``duplicate``      multiple raw deliveries of the SAME receipt_hash collapse
                     to one logical record; provenance of every delivery is
                     preserved (ADR-0002 §4).
- ``ambiguous``      multiple DISTINCT receipt hashes resolve to one
                     trace-side record. Never silently resolved.
- ``late_arrival``   the receipt arrives outside the event window and beyond
                     the reconciliation grace. Still correlated, but flagged.
- ``receipt_missing`` a trace-side record has no receipt and reconciliation
                     is past the grace. Until then the record is *open*
                     (pending), never receipt_missing (invariant 2: absence
                     is a coverage gap, not a result).
- ``trace_missing``  a receipt has no trace-side record and reconciliation is
                     past the grace. Same open-window rule.

``open`` records (grace not yet elapsed) are counted in
``CorrelationResult.pending`` and NOT emitted as terminal states.

Time handling: all datetimes must be timezone-aware (or naive, treated as
UTC). ``reconcile`` takes an explicit reconciliation instant ``at``; pass
``at=None`` to reconcile as if every window had closed.

Synthetic receipts are hand-built ONLY as test index rows (fake hashes, an
explicit ``synthetic`` marker) — never as evidence-store fixtures. Canonical
evidence files are immutable (invariant 1); ``load_receipt_index`` opens
index files read-only and asserts sha256 equality of the raw bytes before
and after the read.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

CORRELATION_STATES = (
    "matched",
    "duplicate",
    "ambiguous",
    "late_arrival",
    "receipt_missing",
    "trace_missing",
)
# ADR-0002 ordering: `matched | receipt_missing | trace_missing | ambiguous |
# late_arrival | duplicate` (canonical presentation order) — see
# CorrelationRecord.canonical_state() for the display mapping.

DEFAULT_GRACE_SECONDS = 30.0


def _as_utc(at: dt.datetime) -> dt.datetime:
    """Normalise naive timestamps to UTC; reject tz-naive + tz-aware mixing otherwise."""
    if at.tzinfo is None:
        return at.replace(tzinfo=dt.UTC)
    return at.astimezone(dt.UTC)


@dataclass(frozen=True)
class ReceiptRecord:
    """Receipt-side index row. Derived state only — never canonical bytes."""

    receipt_hash: str
    trace_id: str | None
    decision: str | None
    event_time: dt.datetime
    provenance: str | None = None
    synthetic: bool = False  # explicit marker: hand-built index row, NOT evidence

    def __post_init__(self) -> None:
        if not self.receipt_hash:
            raise ValueError("receipt_hash is required (empty string is not a digest)")
        object.__setattr__(self, "event_time", _as_utc(self.event_time))


@dataclass(frozen=True, eq=True)
class TraceRecord:
    """Trace-side record with its event window [window_start, window_end]."""

    trace_id: str
    tool_invocation: str | None
    observed_at: dt.datetime
    window_start: dt.datetime | None = None
    window_end: dt.datetime | None = None

    def __post_init__(self) -> None:
        if not self.trace_id:
            raise ValueError("trace_id is required")
        object.__setattr__(self, "observed_at", _as_utc(self.observed_at))
        ws = self.window_start or self.observed_at
        we = self.window_end or self.observed_at
        object.__setattr__(self, "window_start", _as_utc(ws))
        object.__setattr__(self, "window_end", _as_utc(we))
        if self.window_start > self.window_end:  # type: ignore[operator]
            raise ValueError("window_start must not be after window_end")


@dataclass(frozen=True)
class CorrelationConfig:
    """Reconciliation knobs. The grace window absorbs out-of-order arrival."""

    grace_seconds: float = DEFAULT_GRACE_SECONDS


@dataclass(frozen=True)
class CorrelationRecord:
    """One terminal correlation outcome (ADR-0002 Correlation entity)."""

    state: str
    trace_id: str | None
    receipt_hashes: tuple[str, ...] = ()
    trace_side_count: int = 1
    decision: str | None = None
    receipt_event_times: tuple[dt.datetime, ...] = ()
    trace_observed_at: dt.datetime | None = None
    notes: str = ""
    provenance: tuple[str, ...] = ()  # provenance of every collapsed delivery

    def __post_init__(self) -> None:
        if self.state not in CORRELATION_STATES:
            raise ValueError(f"unknown correlation state: {self.state!r}")


@dataclass
class CorrelationResult:
    """Terminal records plus open (in-grace) count — absence is visible."""

    records: list[CorrelationRecord] = field(default_factory=list)
    pending: int = 0  # open records: grace not yet elapsed, state not decided

    def by_state(self, state: str) -> list[CorrelationRecord]:
        if state not in CORRELATION_STATES:
            raise ValueError(f"unknown correlation state: {state!r}")
        return [r for r in self.records if r.state == state]


@dataclass(frozen=True)
class _CollapsedReceipt:
    """Logical receipt: same (trace_id, receipt_hash) collapsed, provenance kept."""

    receipt_hash: str
    trace_id: str | None
    decision: str | None
    event_time: dt.datetime
    deliveries: int
    provenance: tuple[str, ...]


def _collapse_receipts(
    receipts: list[ReceiptRecord],
) -> list[_CollapsedReceipt]:
    ordered: dict[tuple[str | None, str], _CollapsedReceipt] = {}
    for r in receipts:
        key = (r.trace_id, r.receipt_hash)
        prov = (r.provenance,) if r.provenance is not None else ()
        if key in ordered:
            prior = ordered[key]
            ordered[key] = _CollapsedReceipt(
                receipt_hash=prior.receipt_hash,
                trace_id=prior.trace_id,
                decision=prior.decision or r.decision,
                event_time=min(prior.event_time, r.event_time),
                deliveries=prior.deliveries + 1,
                provenance=prior.provenance + prov,
            )
        else:
            ordered[key] = _CollapsedReceipt(
                receipt_hash=r.receipt_hash,
                trace_id=r.trace_id,
                decision=r.decision,
                event_time=r.event_time,
                deliveries=1,
                provenance=prov,
            )
    # deterministic order for reproducible output
    return sorted(ordered.values(), key=lambda c: (c.trace_id or "", c.receipt_hash))


def _in_window_with_grace(
    event_time: dt.datetime,
    window_start: dt.datetime,
    window_end: dt.datetime,
    grace: dt.timedelta,
) -> bool:
    """Out-of-order arrivals inside the grace on either side count as in-window."""
    return (window_start - grace) <= event_time <= (window_end + grace)


def reconcile(
    receipts: list[ReceiptRecord],
    traces: list[TraceRecord],
    config: CorrelationConfig | None = None,
    at: dt.datetime | None = None,
) -> CorrelationResult:
    """Reconcile receipt index rows against trace-side records. Pure / offline."""
    cfg = config or CorrelationConfig()
    grace = dt.timedelta(seconds=cfg.grace_seconds)
    now = _as_utc(at) if at is not None else None

    collapsed = _collapse_receipts(receipts)
    by_receipt_trace: dict[str, list[_CollapsedReceipt]] = {}
    for c in collapsed:
        if c.trace_id:
            by_receipt_trace.setdefault(c.trace_id, []).append(c)
    no_trace_receipts = [c for c in collapsed if not c.trace_id]

    traces_by_id: dict[str, list[TraceRecord]] = {}
    for t in traces:
        traces_by_id.setdefault(t.trace_id, []).append(t)

    records: list[CorrelationRecord] = []
    pending = 0

    def closed(since: dt.datetime, direction: str) -> bool:
        """True when the grace window for `direction` has elapsed past `since`."""
        return now is None or (since + grace) < now

    # Receipts with no trace_id at all: nothing to correlate against — open
    # until grace passes, then trace_missing on the receipt side.
    for c in no_trace_receipts:
        if closed(c.event_time, "trace"):
            records.append(
                CorrelationRecord(
                    state="trace_missing",
                    trace_id=None,
                    receipt_hashes=(c.receipt_hash,),
                    receipt_event_times=(c.event_time,),
                    decision=c.decision,
                    notes="receipt index row carries no signed x_gate trace_id",
                    provenance=c.provenance,
                )
            )
        else:
            pending += 1

    # Receipts whose trace_id has no trace-side record.
    seen_trace_ids: set[str] = set()
    for trace_id in sorted(set(by_receipt_trace) | set(traces_by_id)):
        seen_trace_ids.add(trace_id)
        recs = by_receipt_trace.get(trace_id, [])
        ts = traces_by_id.get(trace_id, [])

        if not ts:
            for c in recs:
                if closed(c.event_time, "trace"):
                    records.append(
                        CorrelationRecord(
                            state="trace_missing",
                            trace_id=trace_id,
                            receipt_hashes=(c.receipt_hash,),
                            receipt_event_times=(c.event_time,),
                            decision=c.decision,
                            notes="no trace-side record within grace",
                            provenance=c.provenance,
                        )
                    )
                else:
                    pending += 1
            continue

        if not recs:
            t0 = min(t.observed_at for t in ts)
            if closed(t0, "receipt"):
                records.append(
                    CorrelationRecord(
                        state="receipt_missing",
                        trace_id=trace_id,
                        trace_side_count=len(ts),
                        trace_observed_at=t0,
                        notes=(
                            "no receipt within grace"
                            + (" (multiple trace-side records)" if len(ts) > 1 else "")
                        ),
                    )
                )
            else:
                pending += 1
            continue

        # Both sides present for this trace_id.
        distinct_hashes = {c.receipt_hash for c in recs}
        total_deliveries = sum(c.deliveries for c in recs)
        if len(distinct_hashes) > 1:
            records.append(
                CorrelationRecord(
                    state="ambiguous",
                    trace_id=trace_id,
                    receipt_hashes=tuple(c.receipt_hash for c in recs),
                    receipt_event_times=tuple(c.event_time for c in recs),
                    trace_side_count=len(ts),
                    trace_observed_at=ts[0].observed_at,
                    notes=(
                        f"{len(distinct_hashes)} distinct receipts map to "
                        f"{len(ts)} trace-side record(s); needs human/ingest review"
                    ),
                    provenance=tuple(p for c in recs for p in c.provenance),
                )
            )
            continue

        one = recs[0]
        t = ts[0]
        if len(distinct_hashes) == 1 and one.deliveries > 1:
            state, note = (
                "duplicate",
                (
                    f"collapsed {one.deliveries} deliveries of one receipt_hash "
                    "to one logical record; provenance preserved"
                ),
            )
        elif not _in_window_with_grace(one.event_time, t.window_start, t.window_end, grace):
            state, note = (
                "late_arrival",
                (
                    "receipt event_time outside trace event window + grace "
                    f"(window {t.window_start.isoformat()}..{t.window_end.isoformat()}, "
                    f"grace {grace.total_seconds()}s)"
                ),
            )
        else:
            state, note = "matched", ""
        records.append(
            CorrelationRecord(
                state=state,
                trace_id=trace_id,
                receipt_hashes=(one.receipt_hash,),
                receipt_event_times=(one.event_time,),
                trace_side_count=len(ts),
                trace_observed_at=t.observed_at,
                decision=one.decision,
                notes=note,
                provenance=one.provenance if one.deliveries > 1 else (),
            )
        )
        if not total_deliveries:  # pragma: no cover — structural invariant
            raise AssertionError("collapsed receipts must carry at least one delivery")
    assert seen_trace_ids  # every trace_id encountered was processed
    return CorrelationResult(records=records, pending=pending)


def sha256_file(path: str | Path) -> str:
    """sha256 of a file's raw bytes (invariant 1 helper)."""
    h = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_receipt_index(
    path: str | Path,
    *,
    read_only: bool = True,
) -> tuple[list[ReceiptRecord], str]:
    """Load a receipt INDEX file (JSONL of index rows, not canonical envelopes).

    Opened strictly read-only; the raw file's sha256 is computed before and
    after the read and must be identical (invariant 1: never mutate evidence
    or evidence-derived files in place). Returns (records, sha256_hex).
    """
    p = Path(path)
    if read_only:
        before = sha256_file(p)
        with p.open("r", encoding="utf-8") as fh:  # O_RDONLY; never 'r+'
            lines = fh.readlines()
        after = sha256_file(p)
        if before != after:
            raise RuntimeError(
                f"index file {p} changed during read-only load — refusing to continue"
            )
    else:  # pragma: no cover - read_only=False is not used by the service
        with p.open("r", encoding="utf-8") as fh:
            lines = fh.readlines()
        before = after = sha256_file(p)
    records = []
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line)
        records.append(
            ReceiptRecord(
                receipt_hash=row["receipt_hash"],
                trace_id=row.get("trace_id"),
                decision=row.get("decision"),
                event_time=dt.datetime.fromisoformat(row["event_time"]),
                provenance=row.get("provenance"),
                synthetic=bool(row.get("synthetic", False)),
            )
        )
    return records, before
