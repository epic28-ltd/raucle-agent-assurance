#!/usr/bin/env python3
"""QUAL-01 demo: evaluate one two-workflow case under rubric ``qual v1``.

Read-only import of repo fixtures (the EVAL-01 synthetic corpus, built as
test data and marked synthetic in ``metadata``); the demo writes nothing
except its own output file. Run: .venv/bin/python services/quality/demo/demo_qual01.py
"""
# SPDX-License-Identifier: FSL-1.1-ALv2

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT / "services" / "quality" / "src"))

from oaa_quality import (  # noqa: E402  # path bootstrapping must precede imports
    EvalInput,
    StepRecord,
    WorkflowRecord,
    attach_to_callback,
    evaluate,
    load_rubric,
    to_score_api_body,
)

HERE = pathlib.Path(__file__).resolve().parent
CORPUS = REPO_ROOT / "tests" / "eval" / "corpus" / "corpus.json"
# Injected clock — the evaluator never reads a wall clock itself.
AT = dt.datetime(2026, 11, 4, 13, 30, tzinfo=dt.UTC)


def build_case(case: dict) -> EvalInput:
    """Map one synthetic corpus case into evaluator input (two workflow units)."""
    steps = [
        StepRecord(
            step_id=f"{case['case_id']}-s{i}",
            description=f"run {s['tool']} ({s['outcome']})",
            tool=s["tool"],
            outcome=s["outcome"],
            has_evidence=bool(s["emit_tool_audit"]),
            privileged=bool(s["privileged"]),
        )
        for i, s in enumerate(case["steps"])
    ]
    half = (len(steps) + 1) // 2
    workflows = (
        WorkflowRecord(
            workflow_id=f"{case['case_id']}-wf-A",
            description=case["description"],
            steps=tuple(steps[:half]),
        ),
        WorkflowRecord(
            workflow_id=f"{case['case_id']}-wf-B",
            description=case["description"],
            steps=tuple(steps[half:]),
        ),
    )
    return EvalInput(
        evaluated_ref=f"eval-case:{case['case_id']}",
        scenario_class=case["scenario_class"],
        workflows=workflows,
        declared_scope=("shell",),
        synthetic=True,
    )


def main() -> int:
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    # one multi_step case split across two workflows (workflow-two demo case)
    multi = next(c for c in corpus["cases"] if c["case_id"] == "MULTI-086")
    # plus a case from a scenario class outside the rubric's allow-list, to show abstention
    blocked = next(c for c in corpus["cases"] if c["scenario_class"] == "sensitive_data")

    rubric = load_rubric(REPO_ROOT / "services" / "quality" / "rubrics" / "qual-v1.yaml")
    scored = evaluate(rubric, build_case(multi), at=AT)
    abstained = evaluate(rubric, build_case(blocked), at=AT)

    sink_events: list[dict] = []
    attach_to_callback(scored, sink_events.append)  # callback-style sink

    out = {
        "rubric": {"rubric_id": rubric.rubric_id, "rubric_version": rubric.rubric_version},
        "scored": to_score_api_body(scored),
        "abstained": to_score_api_body(abstained),
        "span_attributes": sink_events[0],
    }
    (HERE / "demo_output.json").write_text(
        json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"scored:     {scored.evaluated_ref} score={scored.score} uncertainty={scored.uncertainty}"
    )
    print(f"abstained:  {abstained.evaluated_ref} -> {abstained.applicability}")
    print(f"wrote {HERE / 'demo_output.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
