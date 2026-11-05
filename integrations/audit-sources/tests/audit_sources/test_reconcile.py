# SPDX-License-Identifier: Apache-2.0
"""K2 reconciliation tests: ADR-0002 states + ADR-0004 bypass table-driven."""

from __future__ import annotations

import datetime as dt
import re

import pytest
from oaa_audit_sources.normalize import AuditCandidate, normalize_cloudtrail
from oaa_audit_sources.reconcile import (
    ReceiptIndexRow,
    ReconciliationConventions,
    _collapse_candidates,
    reconcile,
)
from test_normalize_cloudtrail import (
    GATE_SESSION_TOKEN,
    RECEIPT_HASH,
    cloudtrail_event,
)

SYNTH_FAKE_TOKEN_FP = "sha256:" + "f" * 8 + ":0000"  # synthetic-only fingerprint value

CONVENTIONS = ReconciliationConventions(
    source="aws_cloudtrail",
    privileged_ops=frozenset({"ec2.run_instances", "secretsmanager.get_secret_value"}),
)
GITHUB_CONV_FIELDS = ReconciliationConventions(
    source="github_audit",
    binding_token_prefix=None,
    privileged_ops=frozenset({"git.clone"}),
)

NOW = dt.datetime(2026, 11, 4, 10, 5, 0, tzinfo=dt.UTC)  # past every grace


def aws_row(receipt_hash: str = RECEIPT_HASH, /, **over: object) -> ReceiptIndexRow:
    return ReceiptIndexRow(
        receipt_hash=receipt_hash,
        event_time=dt.datetime(2026, 11, 4, 10, 0, 30, tzinfo=dt.UTC),
        actor="agent:raucle-e2e",
        decision="allow",
        provenance="test:index-row",
        synthetic=True,
        **over,  # type: ignore[arg-type]
    )


def github_binding_candidate(binding: str | None = SYNTH_FAKE_TOKEN_FP) -> AuditCandidate:
    return AuditCandidate(
        source="github_audit",
        source_event_id="TESTIDAAAA1111",
        event_time="2026-11-04T10:00:05Z",
        actor="octocat-agent[bot]",
        action="git.clone",
        resource="acme/agent-sandbox",
        session_binding=binding,
        raw_ref={"actor_is_agent": True},
        synthetic=True,
    )


def github_row(receipt_hash: str, **over: object) -> ReceiptIndexRow:
    return ReceiptIndexRow(
        receipt_hash=receipt_hash,
        event_time=dt.datetime(2026, 11, 4, 10, 0, 6, tzinfo=dt.UTC),
        actor="octocat-agent[bot]",
        decision="allow",
        hashed_token=SYNTH_FAKE_TOKEN_FP,
        provenance="test:github-index-row",
        synthetic=True,
        **over,  # type: ignore[arg-type]
    )


def test_table_reconciliation_states() -> None:
    """Table: one row per canonical ADR-0002/0004 scenario."""
    cand = AuditCandidate(
        source="aws_cloudtrail",
        source_event_id="ev-1",
        event_time="2026-11-04T10:00:00Z",
        actor="agent:raucle-e2e",
        action="ec2.run_instances",
        resource=None,
        session_binding=None,
        synthetic=True,
    )
    late_receipt = ReceiptIndexRow(
        receipt_hash=RECEIPT_HASH,
        event_time=dt.datetime(2026, 11, 4, 10, 2, 1, tzinfo=dt.UTC),  # 121s off
        actor="someone-else",
        synthetic=True,
    )
    table = [
        # (name, candidates, rows, at, expected states, notes-regex fragment)
        (
            "binding-matched",
            [AuditCandidate(**{**cand.__dict__, "session_binding": GATE_SESSION_TOKEN})],
            [aws_row()],
            NOW,
            ["matched"],
            r"binding token equality",
        ),
        (
            "degraded",
            [cand],  # no binding, actor + 30s window agree
            [aws_row()],
            NOW,
            ["matched_degraded"],
            r"LOWER CONFIDENCE",
        ),
        (
            "bypass-suspected",
            [cand],  # privileged, NO receipt
            [],
            NOW,
            ["bypass_suspected"],
            r"never intent attribution",
        ),
        (
            "receipt-missing-unprivileged",
            [AuditCandidate(**{**cand.__dict__, "action": "s3.get_object"})],
            [],
            NOW,
            ["receipt_missing"],
            r"not a bypass finding",
        ),
        (
            "receipt-only-gap",
            [],
            [aws_row()],
            NOW,
            ["receipt_only_gap"],
            ["NOT proof of non-execution"],
        ),
        (
            "ambiguous-degraded",
            [cand],
            [aws_row(), aws_row("f" * 64)],
            NOW,
            ["ambiguous"],
            r"needs review",
        ),
        (
            "duplicate-receipt-deliveries",
            [cand],
            [aws_row(), aws_row()],  # same receipt_hash twice
            NOW,
            ["duplicate"],
            r"provenance preserved",
        ),
        (
            "duplicate-candidate-deliveries",
            [cand, cand],
            [aws_row()],
            NOW,
            ["duplicate"],
            r"provenance preserved",
        ),
        (
            "out-of-window-unprivileged",
            [AuditCandidate(**{**cand.__dict__, "action": "s3.get_object"})],
            [late_receipt],
            NOW,
            ["receipt_missing", "receipt_only_gap"],
            ["not a bypass finding", "NOT proof of non-execution"],
        ),
    ]
    for name, candidates, rows, at, expected_states, notes_rxs in table:
        result = reconcile(candidates, rows, CONVENTIONS, at=at)
        states = [r.state for r in result.records]
        assert states == expected_states, f"{name}: states {states}"
        if expected_states == ["ambiguous"]:
            continue
        for record, note_rx in zip(result.records, notes_rxs, strict=False):
            assert record.confidence in ("high", "medium", "low")
            assert re.search(note_rx, record.notes), f"{name}: notes {record.notes!r}"


def test_bypass_positive_privileged_no_receipt() -> None:
    cand = AuditCandidate(
        source="aws_cloudtrail",
        source_event_id="ev-bypass",
        event_time="2026-11-04T10:00:00Z",
        actor="agent:raucle-e2e",
        action="secretsmanager.get_secret_value",
        resource="AWS::SecretsManager::Secret/oaa/e2e",
        session_binding=None,
        synthetic=True,
    )
    result = reconcile([cand], [], CONVENTIONS, at=NOW)
    (record,) = result.records
    assert record.state == "bypass_suspected"
    assert record.confidence == "high"
    assert record.match_method is None
    assert "SEC-009" in record.notes
    # no intent attribution, ever (ADR-0004 §2/§5): no agent-blaming language
    assert "intent attribution" in record.notes
    assert "the agent bypassed" not in record.notes.lower()


def test_receipt_only_gap_is_evidence_gap_not_non_execution() -> None:
    row = aws_row()
    result = reconcile([], [row], CONVENTIONS, at=NOW)
    (record,) = result.records
    assert record.state == "receipt_only_gap"
    assert record.confidence == "low"
    assert record.candidate_event_id is None
    assert "evidence_gap per ADR-0004" in record.notes
    assert "NOT proof of non-execution" in record.notes


def test_degraded_vs_binding_match_confidence() -> None:
    cand_bound = AuditCandidate(
        source="aws_cloudtrail",
        source_event_id="ev-bound",
        event_time="2026-11-04T10:00:00Z",
        actor="agent:raucle-e2e",
        action="ec2.run_instances",
        resource=None,
        session_binding=GATE_SESSION_TOKEN,
        synthetic=True,
    )
    cand_loose = AuditCandidate(
        source="aws_cloudtrail",
        source_event_id="ev-loose",
        event_time="2026-11-04T10:00:00Z",
        actor="agent:raucle-e2e",
        action="ec2.terminate_instances",
        resource=None,
        session_binding=None,
        synthetic=True,
    )
    rows = [
        aws_row(RECEIPT_HASH),
        ReceiptIndexRow(
            receipt_hash="c" * 64,
            event_time=dt.datetime(2026, 11, 4, 10, 0, 20, tzinfo=dt.UTC),
            actor="agent:raucle-e2e",
            decision="allow",
            synthetic=True,
        ),
    ]
    result = reconcile([cand_bound, cand_loose], rows, CONVENTIONS, at=NOW)
    by_state = {r.candidate_event_id: r for r in result.records}
    assert by_state["ev-bound"].state == "matched"
    assert by_state["ev-bound"].confidence == "high"
    assert by_state["ev-bound"].match_method == "binding"
    assert by_state["ev-loose"].state == "matched_degraded"
    assert by_state["ev-loose"].confidence == "medium"
    assert by_state["ev-loose"].match_method == "time_window+actor"
    # both receipts are claimed: one by binding, one by time+actor
    states = [r.state for r in result.records]
    assert states == ["matched", "matched_degraded"]


def test_ambiguous_two_binding_tokens_on_one_candidate() -> None:
    cand = github_binding_candidate()
    rows = [github_row("c" * 64), github_row("d" * 64)]  # same hashed_token
    result = reconcile([cand], rows, GITHUB_CONV_FIELDS, at=NOW)
    (record,) = result.records
    assert record.state == "ambiguous"
    assert record.confidence == "low"
    assert record.match_method == "binding"
    assert record.receipt_hashes == ("c" * 64, "d" * 64)


def test_github_binding_match_and_convention() -> None:
    result = reconcile(
        [github_binding_candidate()],
        [github_row("e" * 64)],
        GITHUB_CONV_FIELDS,
        at=NOW,
    )
    (record,) = result.records
    assert record.state == "matched"
    assert record.confidence == "high"
    assert record.match_method == "binding"
    assert record.source == "github_audit"


def test_pending_when_grace_not_elapsed() -> None:
    cand = github_binding_candidate(binding=None)
    at = dt.datetime(2026, 11, 4, 10, 0, 20, tzinfo=dt.UTC)
    result = reconcile([cand], [], GITHUB_CONV_FIELDS, at=at)
    assert result.records == []
    assert result.pending == 1


def test_receipt_only_gap_pending_inside_grace() -> None:
    row = aws_row()
    at = dt.datetime(2026, 11, 4, 10, 0, 40, tzinfo=dt.UTC)  # < 30s after row
    result = reconcile([], [row], CONVENTIONS, at=at)
    assert result.records == []
    assert result.pending == 1


def test_window_boundary_degrades_out() -> None:
    cand = AuditCandidate(
        source="aws_cloudtrail",
        source_event_id="ev-edge",
        event_time="2026-11-04T10:00:00Z",
        actor="agent:raucle-e2e",
        action="ec2.run_instances",
        resource=None,
        session_binding=None,
        synthetic=True,
    )
    row = ReceiptIndexRow(
        receipt_hash=RECEIPT_HASH,
        event_time=dt.datetime(2026, 11, 4, 10, 2, 1, tzinfo=dt.UTC),  # 121s off
        actor="agent:raucle-e2e",
        synthetic=True,
    )
    result = reconcile([cand], [row], CONVENTIONS, at=NOW)
    assert [r.state for r in result.records] == ["bypass_suspected", "receipt_only_gap"]


def test_candidates_from_real_normalizer_flow_end_to_end() -> None:
    """CloudTrail export -> candidates -> reconcile against gate-set tokens."""
    cands = normalize_cloudtrail([cloudtrail_event()], synthetic=True)
    result = reconcile(cands, [aws_row()], CONVENTIONS, at=NOW)
    (record,) = result.records
    assert record.state == "matched"
    assert record.match_method == "binding"
    assert record.candidate_event_time == "2026-11-04T10:00:00Z"


def test_wrong_source_candidates_rejected() -> None:
    cand = github_binding_candidate()
    with pytest.raises(ValueError, match="one source at a time"):
        reconcile([cand], [], CONVENTIONS, at=NOW)


def test_input_validation() -> None:
    with pytest.raises(ValueError, match="unsupported reconciliation source"):
        ReconciliationConventions(source="gcp_audit")
    with pytest.raises(ValueError, match="receipt_hash is required"):
        ReceiptIndexRow(receipt_hash="", event_time=dt.datetime.now(dt.UTC))
    with pytest.raises(ValueError, match="unknown reconciliation state"):
        reconcile([], [], CONVENTIONS, at=NOW).by_state("nonexistent")


def test_synthetic_markers_on_all_fixture_inputs() -> None:
    """Every fixture input carries the explicit synthetic marker (invariant)."""
    cands = normalize_cloudtrail([cloudtrail_event()], synthetic=True)
    assert all(c.synthetic for c in cands)
    row = aws_row()
    assert row.synthetic is True


def test_collapse_candidates_rejects_foreign_source():
    cand = AuditCandidate(
        source="github_audit",
        source_event_id="e1",
        event_time="2026-01-01T00:00:00+00:00",
        action="read",
        actor="a",
        resource="r",
        session_binding=None,
    )
    with pytest.raises(ValueError, match="reconcile one source at a time"):
        _collapse_candidates([cand], source="ok")
