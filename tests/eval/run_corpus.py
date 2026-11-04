#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""EVAL-01 — offline replay harness for the synthetic regression corpus.

For each corpus case the harness:

1. builds receipt-index rows (synthetic, fake hashes, ``synthetic=True``) and
   trace-side records from the case spec, runs ``oaa_correlation.reconcile``
   with ``at=None`` (every window closed — fully terminal, deterministic) and
   asserts the correlation-state multiset against the case expectation;
2. feeds the correlation records plus the case's extra index-plane events
   (tool-audit, verification, ingest coverage, custody, identity rows — all
   synthetic) to ``oaa_rules.run_rules`` with the SHIPPED versioned config
   (``services/rules/config/rules.yaml``) and asserts the finding set (SEC
   rule ids + expected suppression retention) against the case expectation;
3. self-checks the case spec: the mocked gate decisions must be consistent
   with the privileged-registry semantics, and every synthetic index row
   carries the ``synthetic`` marker.

Replay is pure offline reconstruction: mocked index-plane events only, no
network, no model calls, no secrets, canonical receipt bytes never
constructed. Findings never carry raw payloads (the engine enforces this).
Evaluators get no tools and no secrets: the whole run is a pure function of
the versioned corpus + versioned rules config.

Usage::

    python tests/eval/run_corpus.py [--write-results PATH]

With ``--write-results`` (or when asserted via pytest) the run produces a
results JSON with one entry per case and a header block with counts.
Exit status is non-zero if any case fails.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys
from datetime import UTC, datetime, timedelta

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parents[2] / "services" / "correlation" / "src")
)
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "services" / "rules" / "src"))

from oaa_rules import Event, load_config, run_rules

from oaa_correlation import (
    CorrelationConfig,
    CorrelationResult,
    ReceiptRecord,
    TraceRecord,
    reconcile,
)

_spec = importlib.util.spec_from_file_location(
    "eval_generate_corpus", pathlib.Path(__file__).resolve().parent / "generate_corpus.py"
)
_generate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_generate)  # type: ignore[union-attr]

HERE = pathlib.Path(__file__).resolve().parent
CORPUS_PATH = HERE / "corpus" / "corpus.json"
RULES_CONFIG_PATH = (
    pathlib.Path(__file__).resolve().parents[2] / "services" / "rules" / "config" / "rules.yaml"
)

CORRELATION_STATES = frozenset(
    {"matched", "duplicate", "ambiguous", "late_arrival", "receipt_missing", "trace_missing"}
)
GATES = frozenset({"allow", "deny"})


def load_corpus() -> dict:
    with CORPUS_PATH.open(encoding="utf-8") as fh:
        return json.load(fh)


# ------------------------------------------------------------ spec building ----


def _step_time(case: dict, step_index: int) -> datetime:
    base = datetime.fromisoformat(case["metadata"]["base_time_utc"])
    return base.replace(tzinfo=None) + timedelta(
        seconds=step_index * case["metadata"]["step_gap_seconds"]
    )


def _extra_time(case: dict, extra_event: dict) -> datetime:
    base = datetime.fromisoformat(case["metadata"]["base_time_utc"])
    return base.replace(tzinfo=None) + timedelta(minutes=extra_event["offset_minutes"])


def build_receipts_and_traces(case: dict) -> tuple[list[ReceiptRecord], list[TraceRecord]]:
    """Synthetic receipt INDEX rows (fake hashes, synthetic marker) and
    trace-side records per mocked step. Trace records are absent exactly when
    the expected state is ``trace_missing``; receipts are absent exactly when
    the expected state is ``receipt_missing``."""
    receipts: list[ReceiptRecord] = []
    traces: list[TraceRecord] = []
    for idx, step in enumerate(case["steps"]):
        corr = step["correlation"]
        assert corr in CORRELATION_STATES, corr
        at = _step_time(case, idx)
        if corr != "receipt_missing":
            hashes = [_generate._fake_hash(case["case_id"], step["trace_id"])]
            if corr == "ambiguous":
                hashes.append(_generate._fake_hash(case["case_id"], step["trace_id"], "alt"))
            deliveries = 2 if corr == "duplicate" else 1
            event_time = at.replace(tzinfo=UTC) + (
                timedelta(seconds=300) if corr == "late_arrival" else timedelta(0)
            )
            for k in range(deliveries):
                receipts.append(
                    ReceiptRecord(
                        receipt_hash=hashes[0],
                        trace_id=step["trace_id"],
                        decision=step["gate"],
                        event_time=event_time,
                        provenance=f"synthetic-test-harness:delivery-{k}",
                        synthetic=True,
                    )
                )
            if corr == "ambiguous":
                receipts.append(
                    ReceiptRecord(
                        receipt_hash=hashes[1],
                        trace_id=step["trace_id"],
                        decision=step["gate"],
                        event_time=at.replace(tzinfo=UTC) + timedelta(seconds=5),
                        provenance="synthetic-test-harness:ambiguous-alt",
                        synthetic=True,
                    )
                )
        if corr != "trace_missing":
            traces.append(
                TraceRecord(
                    trace_id=step["trace_id"],
                    tool_invocation=step["tool"],
                    observed_at=at.replace(tzinfo=UTC),
                    window_start=at.replace(tzinfo=UTC) - timedelta(seconds=5),
                    window_end=at.replace(tzinfo=UTC) + timedelta(seconds=15),
                )
            )
    return receipts, traces


def build_rules_events(case: dict, result) -> list[Event]:
    """Index-plane events for the rules engine: correlation records from the
    reconcile result + the case's synthetic tool-audit and extra events."""
    events: list[Event] = []
    tool_by_trace = {s["trace_id"]: s["tool"] for s in case["steps"] if "trace_id" in s}
    for rec in result.records:
        trace_key = rec.trace_id or str(rec.receipt_hashes[:1])
        at = rec.trace_observed_at or (
            rec.receipt_event_times[0] if rec.receipt_event_times else None
        )
        assert at is not None, "every record has a trace or receipt timestamp"
        events.append(
            Event(
                kind="correlation",
                at=at,
                ref=f"corr:{trace_key}",
                trace_id=rec.trace_id or None,
                tool=tool_by_trace.get(rec.trace_id) if rec.trace_id else None,
                agent_id=case["agent_id"],
                application=case["application"],
                state=rec.state,
                decision=rec.decision,
                synthetic=True,
            )
        )
    for i, step in enumerate(case["steps"]):
        if step["emit_tool_audit"]:
            events.append(
                Event(
                    kind="tool_audit",
                    at=_step_time(case, i),
                    ref=f"ta:{step['trace_id']}",
                    tool=step["tool"],
                    agent_id=case["agent_id"],
                    application=case["application"],
                    trace_id=step["trace_id"],
                    decision=step["gate"],
                    outcome=step["outcome"],
                    privileged=step["privileged"],
                    release_id=step.get("release_id"),
                    synthetic=True,
                )
            )
    for j, extra_event in enumerate(case["extra_index_events"]):
        events.append(
            Event(
                kind=extra_event["kind"],
                at=_extra_time(case, extra_event),
                ref=f"extra:{j}",
                agent_id=extra_event.get("agent_id", case["agent_id"]),
                tool=extra_event.get("tool"),
                application=case["application"],
                receipt_hash=extra_event.get("receipt_hash"),
                state=extra_event.get("state"),
                decision=None,
                outcome=None,
                credential_id=extra_event.get("credential_id"),
                action=extra_event.get("action"),
                chain_seq=extra_event.get("chain_seq"),
                producer_id=extra_event.get("producer_id"),
                release_id=extra_event.get("release_id"),
                content=extra_event.get("content"),
                synthetic=True,
            )
        )
    return events


# ------------------------------------------------------------ expectations ----


def _empty_result_placeholder() -> CorrelationResult:
    """CorrelationResult with zero records for extras-only cases (no index)."""
    return CorrelationResult(records=[], pending=0)


def check_case(case: dict, config) -> dict:
    """Replay one case offline. Returns a result dict; AssertionError on any
    mismatched expectation (pytest turns this into a failing assertion)."""
    receipts, traces = build_receipts_and_traces(case)
    # Cases whose workload lives in extra index events (verification/ingest
    # coverage) have no receipt or trace rows: nothing to correlate — the
    # expected correlation map is empty by construction.
    result = (
        reconcile(receipts, traces, CorrelationConfig(), at=None)
        if receipts or traces
        else _empty_result_placeholder()
    )

    # correlation-state expectations
    actual_corr: dict[str, str] = {}
    for rec in result.records:
        if rec.trace_id is not None:
            actual_corr[rec.trace_id] = rec.state
    assert result.pending == case["expected"]["pending"], (
        f"{case['case_id']}: pending {result.pending} != {case['expected']['pending']}"
    )
    assert actual_corr == case["expected"]["correlation"], (
        f"{case['case_id']}: correlation {actual_corr} != {case['expected']['correlation']}"
    )
    for rec in result.records:
        for h in rec.receipt_hashes:
            assert h.startswith("sha256:") and h.count(":") == 1, "fake hash shape"
    assert all(r.synthetic for r in receipts), "synthetic marker on every index row"

    # gate-decision self-consistency of the spec (ground-truth guard)
    for step in case["steps"]:
        gate = step["gate"]
        if gate is None:
            assert step["correlation"] == "receipt_missing", (
                f"{case['case_id']}: a step with no gate must correlate receipt_missing"
            )
        else:
            assert gate in GATES

    findings = run_rules(build_rules_events(case, result), config)
    actual_rules: dict[str, dict] = {}
    for f in findings:
        actual_rules[f.rule_id] = {"suppressed": f.suppression_reason is not None}
    expected_rules = {
        e["rule_id"]: {"suppressed": e["suppressed"]} for e in case["expected"]["rules"]
    }
    assert actual_rules == expected_rules, (
        f"{case['case_id']}: findings {sorted(actual_rules)} != "
        f"expected {sorted(expected_rules)} (class {case['scenario_class']})"
    )
    # findings never carry payloads: every field is a str, tuple, or None
    for f in findings:
        blob = json.dumps(
            {
                "rule_id": f.rule_id,
                "evidence_refs": f.evidence_refs,
                "explanation": f.explanation,
                "subject": f.subject,
            }
        )
        assert (
            "-----BEGIN" not in blob
            and "AKIAFAKE0" not in blob
            and "bearer FAKE" not in blob
            and "password=FAKE" not in blob
        ), f"{case['case_id']}: finding leaked synthetic payload"
    return {
        "case_id": case["case_id"],
        "scenario_class": case["scenario_class"],
        "ok": True,
        "findings": [f.rule_id for f in findings],
        "correlation_states": sorted(actual_corr.values()),
        "event_count": len(result.records)
        + sum(1 for s in case["steps"] if s["emit_tool_audit"])
        + len(case["extra_index_events"]),
    }


def run_corpus(config) -> list[dict]:
    cases = load_corpus()["cases"]
    assert len(cases) == 100, f"corpus must hold EXACTLY 100 cases (got {len(cases)})"
    return [check_case(case, config) for case in cases]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--write-results", default="tests/eval/results.json")
    args = parser.parse_args()
    config = load_config(RULES_CONFIG_PATH)
    results = run_corpus(config)
    counts: dict[str, int] = {}
    rule_counts: dict[str, int] = {}
    for r in results:
        counts[r["scenario_class"]] = counts.get(r["scenario_class"], 0) + 1
        for rid in r["findings"]:
            rule_counts[rid] = rule_counts.get(rid, 0) + 1
    summary_path = pathlib.Path(args.write_results)
    if not summary_path.is_absolute():
        summary_path = pathlib.Path.cwd() / summary_path
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(
        json.dumps(
            {
                "harness": "eval-01-offline-v1",
                "corpus_version": load_corpus()["corpus_version"],
                "config_version": config.version,
                "passed": len(results),
                "failed": 0,
                "per_class": counts,
                "per_rule": dict(sorted(rule_counts.items())),
                "results": results,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(f"EVAL-01 offline replay: {len(results)}/100 cases green")
    print(f"  per-class: {counts}")
    print(f"  rules exercised: {dict(sorted(rule_counts.items()))}")
    print(f"  results: {summary_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
