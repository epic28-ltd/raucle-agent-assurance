# SPDX-License-Identifier: Apache-2.0
"""BEH-01 — labelled-corpus false-positive measurement (REQUIRED gate).

Methodology (docs/beh01-labelled-corpus-methodology.md): the 100-case EVAL
corpus is the labelled window. Benign cases are pooled into one labelled
baseline agent (labels travel outside the events; labels never change a
rule's arithmetic), then EVERY corpus case is replayed per-run against that
baseline. Benign cases flagged by any BEH rule count as false positives.

The FP bound is documented and hard: more benign FPs than the bound fails
the suite. Current measured state: fp_count == 0, precision == 1.0 (the
only flagged cases are multi-step corpus cases, which are labelled
non-benign).
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "services/rules/src"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "services/correlation/src"))

from oaa_rules import (
    Event,
    LabelledRun,
    build_baseline,
    load_config,
    measure_false_positives,
)

_spec = importlib.util.spec_from_file_location(
    "eval_run_corpus", pathlib.Path(__file__).resolve().parent / "run_corpus.py"
)
_run = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_run)  # type: ignore[union-attr]

HERE = pathlib.Path(__file__).resolve().parent
CORPUS = json.loads((HERE / "corpus" / "corpus.json").read_text(encoding="utf-8"))
CONFIG = load_config(HERE.parents[1] / "services" / "rules" / "config" / "rules.yaml")
POOL_AGENT = "agent-pooled-benign"


def corpus_run(case: dict[str, Any], pool: bool = False) -> LabelledRun:
    events: list[Event] = _run.build_rules_events(case, _run._empty_result_placeholder())
    if pool:
        # pool only the agent half of the key; release_id and tool survive,
        # so the BEH-D (SEC-006 reused) semantics stay intact
        events = [
            Event(
                kind=e.kind,
                at=e.at,
                ref=e.ref,
                agent_id=POOL_AGENT,
                tool=e.tool,
                application=e.application,
                trace_id=e.trace_id,
                receipt_hash=e.receipt_hash,
                state=e.state,
                decision=e.decision,
                outcome=e.outcome,
                privileged=e.privileged,
                credential_id=e.credential_id,
                action=e.action,
                lease_id=e.lease_id,
                release_id=e.release_id,
                chain_seq=e.chain_seq,
                producer_id=e.producer_id,
                authenticated=e.authenticated,
                content=e.content,
                synthetic=e.synthetic,
            )
            for e in events
        ]
    return LabelledRun(case["case_id"], case["scenario_class"], tuple(events))


def measured() -> dict[str, Any]:
    benign = [c for c in CORPUS["cases"] if c["scenario_class"] == "benign"]
    baseline = build_baseline([corpus_run(c, pool=True) for c in benign], label="pooled-benign")
    return measure_false_positives(baseline, [corpus_run(c) for c in CORPUS["cases"]], CONFIG)


def test_corpus_fp_measurement_within_documented_bound() -> None:
    """HARD GATE: benign-labelled cases flagged by BEH rules must stay within
    the documented bound (<= 15% of benign cases). The drift rules exist to
    catch real shifts; a benign FP storm would make them advisory noise."""
    m = measured()
    assert m["fp_count"] <= m["fp_bound"], (m["fp_count"], m["fp_bound"], m["fp_cases"])


def test_corpus_measurement_precision() -> None:
    """Precision over flagged cases: currently no benign case is flagged, so
    precision is exactly 1.0; if flagged cases exist they must be a majority
    non-benign (precision >= 0.5) to keep the advisory rules honest."""
    m = measured()
    if m["cases_flagged"]:
        assert m["precision"] >= 0.5, m
    assert m["precision"] is None or m["precision"] >= 0.5


def test_corpus_drift_rules_fire_on_shifted_classes() -> None:
    """The engine must not be vacuous on the corpus: at least one
    non-benign labelled case carries a BEH finding (multi-step corpus cases
    exceed the pooled benign volume)."""
    m = measured()
    assert m["tp_count"] >= 1, m


def test_corpus_fp_measurement_is_deterministic() -> None:
    assert measured() == measured()


def test_corpus_measurement_shape() -> None:
    m = measured()
    assert m["benign_runs"] == 40 and m["non_benign_runs"] == 60
    assert m["fp_bound"] == 6  # documented: ceil(15% of 40 benign cases)
    assert set(m) >= {
        "benign_runs",
        "non_benign_runs",
        "cases_flagged",
        "fp_count",
        "fp_cases",
        "tp_count",
        "tp_cases",
        "precision",
        "fp_bound",
    }
