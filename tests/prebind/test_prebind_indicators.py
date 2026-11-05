# SPDX-License-Identifier: Apache-2.0

"""OV-12: Prebind Assurance indicators derived from committed gate evidence.

Fixtures come straight from the committed demo data (synthetic receipt
index, runs.json, red findings) plus inline edge cases. Everything is
deterministic and offline.
"""

from __future__ import annotations

import json
from pathlib import Path

from oaa_prebind.derive import (
    DERIVABLE_STATES,
    PREBIND_ENFORCEMENT_WEAKNESS_RULES,
    PREBIND_STATES,
    derive_receipt_state_from_runs,
    load_receipt_index,
    prebind_indicators,
)

DEMO = Path(__file__).resolve().parents[2] / "services" / "investigation-ui" / "demo_data"


def _receipts() -> list[dict]:
    return load_receipt_index(DEMO / "synthetic_receipt_index.jsonl")


def _runs() -> dict:
    return json.loads((DEMO / "runs.json").read_text(encoding="utf-8"))


def _findings() -> list[dict]:
    return json.loads((DEMO / "red_findings.json").read_text(encoding="utf-8"))["findings"]


def test_state_vocabulary_is_the_cage1_set() -> None:
    assert set(PREBIND_STATES) == {
        "admitted",
        "held",
        "narrowed",
        "escalated",
        "refused",
        "quarantined",
        "no_bind",
        "unresolved",
    }


def test_demo_receipts_cover_allowed_denied_and_legacy_rows() -> None:
    rows = _receipts()
    decisions = {r["decision"] for r in rows}
    assert "allow" in decisions and "deny" in decisions
    assert any(r["decision"] is None for r in rows)


def test_demo_receipts_derive_to_admitted_and_refused() -> None:
    indicators = prebind_indicators(_receipts())
    counts = indicators["counts"]
    assert counts["admitted"] > 0
    assert counts["refused"] > 0
    assert counts["unresolved"] > 0


def test_no_decision_recorded_is_unresolved_not_a_fabricated_state() -> None:
    indicators = prebind_indicators(_receipts())
    assert any(a.startswith("no_decision_recorded") for a in indicators["anomalies"])
    # a v0-schema index row must not be read as admitted
    legacy = [a for a in indicators["anomalies"] if a.startswith("legacy_schema:")]
    assert legacy


def test_duplicate_and_ambiguous_receipts_surface_as_anomalies() -> None:
    indicators = prebind_indicators(_receipts())
    assert any(a.startswith("duplicate_receipt:") for a in indicators["anomalies"])
    assert any(a.startswith("ambiguous_trace:") for a in indicators["anomalies"])


def test_missing_receipt_at_gate_is_reported_honestly() -> None:
    rows = derive_receipt_state_from_runs(_runs())
    # run-obs01-01 records a privileged shell span with a decision observed
    # but no receipt: the honest reading is unresolved, never held/quarantined.
    assert rows, "demo data carries at least one missing-receipt privileged span"
    for row in rows:
        assert row["state"] == "unresolved"
        assert any(a.startswith("missing_receipt_at_gate") for a in row["anomalies"])


def test_non_privileged_and_privileged_receipted_spans_are_not_flagged() -> None:
    runs = _runs()
    flagged = {(r["trace_id"], r["span_id"]) for r in derive_receipt_state_from_runs(runs)}
    for run in runs["runs"]:
        for trace in run["traces"]:
            for span in trace["spans"]:
                # a receipted span, or a non-privileged span, is not a
                # missing-receipt anomaly
                if span.get("receipt_hash") or not span.get("privileged"):
                    assert (trace["trace_id"], span["span_id"]) not in flagged


def test_red_findings_map_to_enforcement_weaknesses() -> None:
    indicators = prebind_indicators(_receipts(), red_findings=_findings())
    weaknesses = indicators["enforcement_weaknesses"]
    assert set(weaknesses) <= set(PREBIND_ENFORCEMENT_WEAKNESS_RULES)
    joined = (
        weaknesses.get("RED-011", [])
        + weaknesses.get("RED-013", [])
        + weaknesses.get("RED-017", [])
    )
    assert all(fid for fid in joined)
    # every weak finding id is a real committed finding id
    committed = {f["finding_id"] for f in _findings()}
    assert set(joined) <= committed


def test_no_bind_counter_is_honest_zero_with_annotation() -> None:
    indicators = prebind_indicators(_receipts())
    assert indicators["counts"]["no_bind"] == 0
    assert indicators["annotation_count"] == len(indicators["annotations"])
    assert any(a.startswith("no_bind: not derivable") for a in indicators["annotations"])


def test_indicator_output_is_deterministic() -> None:
    receipts = _receipts()
    runs = _runs()
    findings = _findings()
    first = json.dumps(
        prebind_indicators(receipts, runs=runs, red_findings=findings),
        sort_keys=True,
    )
    second = json.dumps(
        prebind_indicators(list(reversed(receipts)), runs=runs, red_findings=findings),
        sort_keys=True,
    )
    assert first == second


def test_states_counter_keys_are_complete_and_stable() -> None:
    indicators = prebind_indicators(_receipts())
    assert list(indicators["counts"].keys()) == list(PREBIND_STATES)
    assert set(indicators["derivable_states"]) == set(DERIVABLE_STATES)


def test_empty_evidence_produces_fail_visible_zero_counts() -> None:
    indicators = prebind_indicators([], runs={"runs": []})
    assert indicators["counts"] == dict.fromkeys(PREBIND_STATES, 0)
    assert indicators["derivation_note"].startswith("admitted/refused/unresolved")
