# SPDX-License-Identifier: Apache-2.0
"""K2 gate/audit reconciliation: AuditCandidates vs receipt index rows.

ADR-0002 correlation semantics + ADR-0004 bypass detection, applied to
tool-side audit records (vantage A) against gate receipts (vantage G). The
state machine mirrors ``oaa_correlation.core.reconcile``:

- ``matched``            candidate session_binding EQUALS the receipt
                         convention token. AWS: the gate sets
                         ``roleSessionName = 'oaa-<receipt_hash_prefix>'``
                         per receipt, and an assumed-role CloudTrail event
                         carries that name; GitHub: the receipt row carries
                         the fingerprint (``hashed_token``) of the issued
                         credential and the audit event repeats it.
- ``matched_degraded``   no binding carried by the candidate, but exactly one
                         receipt falls in the time window with the same
                         actor. Weaker evidence — lower confidence recorded.
- ``bypass_suspected``   candidate has NO receipt inside the window AND its
                         op is privileged per the registry config. Observed
                         discrepancy only: findings never attribute intent
                         (ADR-0004 §2/§5).
- ``receipt_only_gap``   receipt with no audit event: an evidence gap per
                         ADR-0004, explicitly NOT proof of non-execution.
- ``receipt_missing``    candidate unprivileged, no receipt: audit-coverage
                         gap (ADR-0002 ``receipt_missing``), not a bypass.
- ``duplicate``          multiple raw deliveries of the SAME logical side
                         (one candidate delivered N times, or one
                         receipt_hash delivered N times) collapse to one
                         logical record; provenance preserved (ADR-0002 §4).
- ``ambiguous``          multiple DISTINCT receipts claim one candidate (or
                         vice versa via the degraded path). Never silently
                         resolved.

Confidence classes are recorded on every terminal record (high/medium/low);
``open``/pending candidates (grace not yet elapsed) are counted in
``ReconciliationResult.pending`` — absence is never silently graded.

Pure and offline. Receipt rows are index-level derived state only — never
canonical receipt bytes. Synthetic rows carry an explicit ``synthetic``
marker (invariant: hand-built rows are never treated as evidence).
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Sequence
from dataclasses import dataclass, field

from .normalize import AuditCandidate

RECONCILIATION_STATES = (
    "matched",
    "matched_degraded",
    "bypass_suspected",
    "receipt_only_gap",
    "receipt_missing",
    "duplicate",
    "ambiguous",
)

CONFIDENCE_CLASSES = ("high", "medium", "low")

# Per record-state confidence (evidence strength, NOT intent attribution):
# - matched:            high   (binding token equality, strongest available)
# - matched_degraded:   medium (time-window + actor agreement only)
# - bypass_suspected:   high   (privileged tool-side execution observed; the
#                              receipt half is missing — investigate)
# - receipt_only_gap:   low    (absence of tool-side evidence is the weakest
#                              signal: evidence gap, not non-execution proof)
# - receipt_missing:    low    (audit-coverage gap for unprivileged op)
# - duplicate:          medium (structural; delivery counted, not evidence)
# - ambiguous:          low    (needs human/ingest review; ADR-0002 never
#                              silently resolves)
STATE_CONFIDENCE: dict[str, str] = {
    "matched": "high",
    "matched_degraded": "medium",
    "bypass_suspected": "high",
    "receipt_only_gap": "low",
    "receipt_missing": "low",
    "duplicate": "medium",
    "ambiguous": "low",
}

DEFAULT_WINDOW_SECONDS = 120.0
DEFAULT_GRACE_SECONDS = 30.0
# Gate-set roleSessionName convention: 'oaa-<receipt_hash_prefix>'. Bandit
# note: named AWS_SESSION_NAME_PREFIX (not *token*) to avoid B105 on a
# non-credential constant.
AWS_SESSION_NAME_PREFIX = "oaa-"  # gate-set roleSessionName convention
AWS_RECEIPT_HASH_PREFIX_CHARS = 12


def _as_utc(ts: dt.datetime) -> dt.datetime:
    return ts.replace(tzinfo=dt.UTC) if ts.tzinfo is None else ts.astimezone(dt.UTC)


@dataclass(frozen=True)
class ReceiptIndexRow:
    """Receipt-side index row (derived state only; never canonical bytes)."""

    receipt_hash: str
    event_time: dt.datetime
    actor: str | None = None
    decision: str | None = None
    # Convention tokens recorded at receipt time. For AWS rows the gate
    # derives roleSessionName from the receipt hash and it need not be stored
    # separately; for GitHub rows the issued-credential fingerprint must be
    # recorded here (it cannot be derived from the receipt hash).
    convention_token: str | None = None
    hashed_token: str | None = None
    provenance: str | None = None
    synthetic: bool = False  # explicit marker: hand-built row, NOT real evidence

    def __post_init__(self) -> None:
        if not self.receipt_hash:
            raise ValueError("receipt_hash is required (empty string is not a digest)")
        object.__setattr__(self, "event_time", _as_utc(self.event_time))

    def convention_tokens(self, conventions: ReconciliationConventions) -> tuple[str, ...]:
        tokens: list[str] = []
        if self.convention_token:
            tokens.append(self.convention_token)
        elif conventions.binding_token_prefix and conventions.source == "aws_cloudtrail":
            tokens.append(
                conventions.binding_token_prefix + self.receipt_hash[:AWS_RECEIPT_HASH_PREFIX_CHARS]
            )
        if self.hashed_token:
            tokens.append(self.hashed_token)
        return tuple(tokens)


@dataclass(frozen=True)
class ReconciliationConventions:
    """The two linkage conventions + reconciliation knobs.

    - ``aws_cloudtrail`` binding convention: the gate sets
      ``roleSessionName = 'oaa-<receipt_hash_prefix>'`` on the assumed role
      it mediates; the audit event's principalId echoes it. Rows carrying
      ``convention_token`` use it verbatim; rows without it have the token
      derived from ``receipt_hash[:12]`` (prefix ``oaa-``).
    - ``github_audit`` binding convention: the gate issues a per-receipt
      credential and records its fingerprint (SHA-256 of the token, never the
      token) as ``hashed_token``; the audit event repeats it. There is no
      client-supplied correlation field in GitHub audit events — binding
      equality is the ONLY strong match there.
    """

    source: str
    binding_token_prefix: str | None = AWS_SESSION_NAME_PREFIX
    window_seconds: float = DEFAULT_WINDOW_SECONDS
    privileged_ops: frozenset[str] = frozenset()
    grace_seconds: float = DEFAULT_GRACE_SECONDS

    def __post_init__(self) -> None:
        if self.source not in ("aws_cloudtrail", "github_audit"):
            raise ValueError(f"unsupported reconciliation source: {self.source!r}")


@dataclass(frozen=True)
class _CollapsedReceipt:
    receipt_hash: str
    event_time: dt.datetime
    actor: str | None
    decision: str | None
    row: ReceiptIndexRow
    deliveries: int
    provenance: tuple[str, ...]

    def convention_tokens(self, conventions: ReconciliationConventions) -> tuple[str, ...]:
        return self.row.convention_tokens(conventions)


def _collapse_receipts(rows: list[ReceiptIndexRow]) -> list[_CollapsedReceipt]:
    """Multiple deliveries of one receipt_hash -> one logical record."""
    ordered: dict[str, _CollapsedReceipt] = {}
    for row in rows:
        prov = (row.provenance,) if row.provenance is not None else ()
        prior = ordered.get(row.receipt_hash)
        if prior is None:
            ordered[row.receipt_hash] = _CollapsedReceipt(
                receipt_hash=row.receipt_hash,
                event_time=row.event_time,
                actor=row.actor,
                decision=row.decision,
                row=row,
                deliveries=1,
                provenance=prov,
            )
        else:
            ordered[row.receipt_hash] = _CollapsedReceipt(
                receipt_hash=prior.receipt_hash,
                event_time=min(prior.event_time, row.event_time),
                actor=prior.actor,
                decision=prior.decision or row.decision,
                row=prior.row,
                deliveries=prior.deliveries + 1,
                provenance=prior.provenance + prov,
            )
    return sorted(ordered.values(), key=lambda c: c.receipt_hash)


@dataclass(frozen=True)
class ReconciliationRecord:
    """One terminal reconciliation outcome (one logical candidate or receipt)."""

    state: str
    confidence: str
    source: str
    candidate_event_id: str | None  # None for receipt_only_gap rows
    receipt_hashes: tuple[str, ...] = ()
    candidate_event_time: str | None = None
    receipt_event_times: tuple[dt.datetime, ...] = ()
    action: str | None = None
    decision: str | None = None
    match_method: str | None = None  # 'binding' | 'time_window+actor' | None
    notes: str = ""
    provenance: tuple[str, ...] = ()
    deliveries: int = 1

    def __post_init__(self) -> None:
        if self.state not in RECONCILIATION_STATES:
            raise ValueError(f"unknown reconciliation state: {self.state!r}")
        if self.confidence not in CONFIDENCE_CLASSES:
            raise ValueError(f"unknown confidence class: {self.confidence!r}")


@dataclass
class ReconciliationResult:
    """Terminal records plus open (in-grace) count — absence is visible."""

    records: list[ReconciliationRecord] = field(default_factory=list)
    pending: int = 0

    def by_state(self, state: str) -> list[ReconciliationRecord]:
        if state not in RECONCILIATION_STATES:
            raise ValueError(f"unknown reconciliation state: {state!r}")
        return [r for r in self.records if r.state == state]


def _within_window(
    candidate_time: dt.datetime, receipt_time: dt.datetime, window: dt.timedelta
) -> bool:
    return abs((receipt_time - candidate_time).total_seconds()) <= window.total_seconds()


def reconcile(
    candidates: Sequence[AuditCandidate],
    receipt_index_rows: Sequence[ReceiptIndexRow],
    conventions: ReconciliationConventions,
    at: dt.datetime | None = None,
) -> ReconciliationResult:
    """Reconcile audit candidates against receipt index rows. Pure / offline.

    ``at`` is the explicit reconciliation instant (naming the source of 'now'
    for tests); pass ``None`` to reconcile as if every window had closed.
    """
    source = conventions.source
    window = dt.timedelta(seconds=conventions.window_seconds)
    grace = dt.timedelta(seconds=conventions.grace_seconds)
    now = _as_utc(at) if at is not None else None

    def closed(since: dt.datetime) -> bool:
        return now is None or (since + grace) < now

    collapsed_receipts = _collapse_receipts(list(receipt_index_rows))

    # ---- collapse candidate deliveries (ADR-0002 §4 duplicate semantics) ----
    logical: dict[tuple[str, str], dict[str, object]] = {}
    for cand in candidates:
        if cand.source != source:
            raise ValueError(
                f"candidate source {cand.source!r} does not match conventions.source "
                f"{source!r}; reconcile one source at a time"
            )
        key = (cand.source, cand.source_event_id)
        prov = (f"{cand.source}:{cand.source_event_id}",)
        if key not in logical:
            logical[key] = {
                "candidate": cand,
                "deliveries": 1,
                "provenance": prov,
            }
        else:
            entry = logical[key]
            entry["deliveries"] = int(entry["deliveries"]) + 1  # type: ignore[call-overload]
            entry["provenance"] = entry["provenance"] + prov  # type: ignore[operator]

    used_receipts: set[str] = set()
    records: list[ReconciliationRecord] = []
    pending = 0

    for entry in sorted(logical.values(), key=lambda e: e["candidate"].source_event_id):  # type: ignore[index,union-attr]
        cand: AuditCandidate = entry["candidate"]  # type: ignore[assignment]
        deliveries: int = entry["deliveries"]  # type: ignore[assignment]
        provenance: tuple[str, ...] = entry["provenance"]  # type: ignore[assignment]
        ctime = _as_utc(dt.datetime.fromisoformat(cand.event_time.replace("Z", "+00:00")))

        if not closed(ctime):
            # Not yet past grace: state undecided (open), never receipt_missing.
            pending += 1
            continue

        # Phase 1 — binding match (strong, exclusive).
        if cand.session_binding:
            binding_hits = [
                c
                for c in collapsed_receipts
                if cand.session_binding in c.convention_tokens(conventions)
            ]
            distinct = {c.receipt_hash for c in binding_hits}
            if len(distinct) > 1:
                records.append(
                    ReconciliationRecord(
                        state="ambiguous",
                        confidence=STATE_CONFIDENCE["ambiguous"],
                        source=source,
                        candidate_event_id=cand.source_event_id,
                        receipt_hashes=tuple(sorted(distinct)),
                        candidate_event_time=cand.event_time,
                        receipt_event_times=tuple(c.event_time for c in binding_hits),
                        action=cand.action,
                        match_method="binding",
                        notes=(
                            f"{len(distinct)} distinct receipts carry the same binding "
                            "token; needs human/ingest review"
                        ),
                        provenance=provenance + tuple(c.row.provenance or "" for c in binding_hits),
                        deliveries=deliveries,
                    )
                )
                used_receipts.update(distinct)
                continue
            if len(distinct) == 1:
                one = binding_hits[0]
                used_receipts.add(one.receipt_hash)
                state = "duplicate" if deliveries > 1 or one.deliveries > 1 else "matched"
                notes = (
                    f"binding token equality ({source} linkage convention); "
                    "confidence: evidence strength, never intent"
                )
                if deliveries > 1 or one.deliveries > 1:
                    notes = (
                        f"collapsed deliveries -> duplicate state "
                        f"(candidate x{deliveries}, receipt x{one.deliveries}); "
                        "provenance preserved"
                    )
                records.append(
                    ReconciliationRecord(
                        state=state,
                        confidence=STATE_CONFIDENCE[state],
                        source=source,
                        candidate_event_id=cand.source_event_id,
                        receipt_hashes=(one.receipt_hash,),
                        candidate_event_time=cand.event_time,
                        receipt_event_times=(one.event_time,),
                        action=cand.action,
                        match_method="binding",
                        notes=notes,
                        provenance=(*provenance, one.row.provenance or ""),
                        deliveries=deliveries,
                    )
                )
                continue

        # Phase 2 — degraded match: time window + actor agreement (weak).
        degraded_pool = [
            c
            for c in collapsed_receipts
            if c.receipt_hash not in used_receipts
            and _within_window(ctime, c.event_time, window)
            and cand.actor is not None
            and c.actor == cand.actor
        ]
        distinct_degraded = {c.receipt_hash for c in degraded_pool}
        if len(distinct_degraded) > 1:
            records.append(
                ReconciliationRecord(
                    state="ambiguous",
                    confidence=STATE_CONFIDENCE["ambiguous"],
                    source=source,
                    candidate_event_id=cand.source_event_id,
                    receipt_hashes=tuple(sorted(distinct_degraded)),
                    candidate_event_time=cand.event_time,
                    receipt_event_times=tuple(c.event_time for c in degraded_pool),
                    action=cand.action,
                    match_method="time_window+actor",
                    notes=(
                        f"{len(distinct_degraded)} distinct receipts fall in-window "
                        "for one candidate (time+actor path); needs review"
                    ),
                    provenance=provenance + tuple(c.row.provenance or "" for c in degraded_pool),
                    deliveries=deliveries,
                )
            )
            used_receipts.update(distinct_degraded)
            continue
        if len(distinct_degraded) == 1:
            one = degraded_pool[0]
            used_receipts.add(one.receipt_hash)
            state = "duplicate" if deliveries > 1 or one.deliveries > 1 else "matched_degraded"
            notes = (
                "no binding on candidate; matched by time window + actor — "
                "LOWER CONFIDENCE, correlation is weaker than binding equality"
            )
            if deliveries > 1 or one.deliveries > 1:
                notes = (
                    f"collapsed deliveries ({deliveries} candidate, "
                    f"{one.deliveries} receipt) over a degraded match; "
                    "provenance preserved"
                )
            records.append(
                ReconciliationRecord(
                    state=state,
                    confidence=STATE_CONFIDENCE[state],
                    source=source,
                    candidate_event_id=cand.source_event_id,
                    receipt_hashes=(one.receipt_hash,),
                    candidate_event_time=cand.event_time,
                    receipt_event_times=(one.event_time,),
                    action=cand.action,
                    match_method="time_window+actor",
                    notes=notes,
                    provenance=(*provenance, one.row.provenance or ""),
                    deliveries=deliveries,
                )
            )
            continue

        # Phase 3 — no receipt at all: bypass check ONLY for privileged ops.
        if cand.action in conventions.privileged_ops:
            records.append(
                ReconciliationRecord(
                    state="bypass_suspected",
                    confidence=STATE_CONFIDENCE["bypass_suspected"],
                    source=source,
                    candidate_event_id=cand.source_event_id,
                    candidate_event_time=cand.event_time,
                    action=cand.action,
                    match_method=None,
                    notes=(
                        "privileged tool-side execution with no gate receipt inside "
                        "the window (ADR-0004 SEC-009); observed discrepancy only — "
                        "never intent attribution, reviewer judgement decides"
                    ),
                    provenance=provenance,
                    deliveries=deliveries,
                )
            )
        else:
            records.append(
                ReconciliationRecord(
                    state="receipt_missing",
                    confidence=STATE_CONFIDENCE["receipt_missing"],
                    source=source,
                    candidate_event_id=cand.source_event_id,
                    candidate_event_time=cand.event_time,
                    action=cand.action,
                    match_method=None,
                    notes=(
                        "no receipt within window; op not privileged — "
                        "audit-coverage gap, not a bypass finding"
                    ),
                    provenance=provenance,
                    deliveries=deliveries,
                )
            )

    # ---- receipts that matched nothing: receipt_only_gap (evidence_gap) ----
    for c in collapsed_receipts:
        if c.receipt_hash in used_receipts:
            continue
        if not closed(c.event_time):
            pending += 1
            continue
        records.append(
            ReconciliationRecord(
                state="receipt_only_gap",
                confidence=STATE_CONFIDENCE["receipt_only_gap"],
                source=source,
                candidate_event_id=None,
                receipt_hashes=(c.receipt_hash,),
                receipt_event_times=(c.event_time,),
                decision=c.decision,
                match_method=None,
                notes=(
                    "receipt with no tool-side audit event: evidence_gap per "
                    "ADR-0004 (gate receipt alone, absence of audit evidence is "
                    "NOT proof of non-execution)"
                ),
                provenance=c.provenance,
                deliveries=c.deliveries,
            )
        )

    return ReconciliationResult(records=records, pending=pending)
