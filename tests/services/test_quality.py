# SPDX-License-Identifier: Apache-2.0
"""QUAL-01 — optional quality scoring: rubric schema, evaluator, attach, guard.

The evaluator package is an advisory-only surface: deterministic heuristics,
no LLM, no tools, no secrets, no network. These tests enforce both behaviour
and those negative guarantees.
"""

from __future__ import annotations

import ast
import datetime as dt
import json
import os
import pathlib
import re
import sys
from typing import Any

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
QUAL_SRC = REPO_ROOT / "services" / "quality" / "src"
RUBRIC_V1 = REPO_ROOT / "services" / "quality" / "rubrics" / "qual-v1.yaml"

for _p in (str(QUAL_SRC),):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from oaa_quality import (  # noqa: E402
    EvalInput,
    StepRecord,
    WorkflowRecord,
    attach_to_callback,
    attach_to_span,
    evaluate,
    load_rubric,
    rubric_from_dict,
    to_score_api_body,
    to_span_attributes,
)
from oaa_quality.evaluator import _pct, _uncertainty  # noqa: E402
from oaa_quality.rubric import Criterion, UncertaintyPolicy  # noqa: E402

AT = dt.datetime(2026, 11, 4, 13, 0, tzinfo=dt.UTC)

SRC_PACKAGE = QUAL_SRC / "oaa_quality"


def _good_rubric_dict() -> dict[str, Any]:
    return {
        "rubric_id": "qual",
        "rubric_version": "2-test",
        "criteria": [
            {"id": "completeness", "weight": 0.4, "description": "criterion a"},
            {"id": "evidence_support", "weight": 0.35, "description": "criterion b"},
            {"id": "scope_compliance", "weight": 0.25, "description": "criterion c"},
        ],
        "applicable_to": {"scenario_classes": ["multi_step", "benign"]},
        "uncertainty": {"min_sample_size": 2, "abstain_rule": "abstain_score_if_sample_below_min"},
    }


def wf(
    workflow_id: str,
    *,
    description: str = "do thing",
    n_steps: int = 2,
    evidence: bool = True,
    tools: tuple[str, ...] = ("shell", "shell"),
) -> WorkflowRecord:
    return WorkflowRecord(
        workflow_id=workflow_id,
        description=description,
        steps=tuple(
            StepRecord(
                step_id=f"{workflow_id}-s{i}",
                description="run",
                tool=tools[i % len(tools)],
                outcome="success",
                has_evidence=evidence,
            )
            for i in range(n_steps)
        ),
    )


# ------------------------------------------------------------ rubric schema ----


def test_rubric_v1_loads_and_validates() -> None:
    rubric = load_rubric(RUBRIC_V1)
    assert rubric.rubric_id == "qual"
    assert rubric.rubric_version == "1"
    assert rubric.criterion_ids == ("completeness", "evidence_support", "scope_compliance")
    assert abs(sum(c.weight for c in rubric.criteria) - 1.0) < 1e-6
    assert rubric.applicable_to.covers("multi_step")
    assert not rubric.applicable_to.covers("prompt_injection")
    assert rubric.uncertainty.min_sample_size == 2


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("rubric_version"),
        lambda d: d["criteria"][0].__setitem__("weight", 0.9),  # weights no longer sum to 1
        lambda d: d["criteria"][1].__setitem__("weight", 0),  # weight out of (0, 1]
        lambda d: d["criteria"].append(dict(d["criteria"][0])),  # duplicate id
        lambda d: d["applicable_to"].__setitem__("scenario_classes", []),  # empty allow-list
        lambda d: d["uncertainty"].__setitem__("min_sample_size", 0),
        lambda d: d["uncertainty"].__setitem__("abstain_rule", ""),
    ],
)
def test_rubric_schema_rejects_malformed(mutate: Any) -> None:
    data = _good_rubric_dict()
    mutate(data)
    with pytest.raises(ValueError):
        rubric_from_dict(data)


def test_rubric_criteria_sorted_and_weights_positive() -> None:
    rubric = rubric_from_dict(_good_rubric_dict())
    assert rubric.criterion_ids == ("completeness", "evidence_support", "scope_compliance")


def test_uncertainty_policy_rejects_bad() -> None:
    with pytest.raises(ValueError):
        UncertaintyPolicy(min_sample_size=-1, abstain_rule="x")
    with pytest.raises(ValueError):
        Criterion(id="x", weight=True, description="no")


# ------------------------------------------------------ applicability/abstain ----


def make_case(
    scenario_class: str = "multi_step",
    n: int = 2,
    *,
    declared: tuple[str, ...] = ("shell",),
    evidence: bool = True,
    descriptions: str = "do thing",
    tools: tuple[str, ...] = ("shell", "shell"),
) -> EvalInput:
    return EvalInput(
        evaluated_ref="test:case-1",
        scenario_class=scenario_class,
        workflows=tuple(
            wf(f"wf-{i}", description=descriptions, evidence=evidence, tools=tools)
            for i in range(n)
        ),
        declared_scope=declared,
        synthetic=True,
    )


@pytest.fixture
def rubric_v1() -> Any:
    return load_rubric(RUBRIC_V1)


def eval_of(rubric: Any, case: EvalInput) -> Any:
    return evaluate(rubric, case, at=AT)


def test_applicable_case_scores_with_expected_result(rubric_v1: Any) -> None:
    s = eval_of(rubric_v1, make_case())
    assert s.applicability == "applied"
    assert s.score == 100
    assert s.uncertainty == "medium"  # n=2 == min_sample_size >= 2, < 2*min_sample
    assert s.reviewer_status == "unreviewed"
    assert {r.criterion_id for r in s.criteria_results} == {
        "completeness",
        "evidence_support",
        "scope_compliance",
    }
    assert all(r.score is not None and r.reason for r in s.criteria_results)


@pytest.mark.parametrize(
    "scenario_class", ["prompt_injection", "sensitive_data", "infra_failure", "out_of_scope", ""]
)
def test_non_permitted_scenario_class_abstains(rubric_v1: Any, scenario_class: str) -> None:
    s = eval_of(rubric_v1, make_case(scenario_class=scenario_class))
    assert s.score is None
    assert s.applicability.startswith("abstained:")
    assert s.uncertainty == "high"
    assert "not in" in s.applicability


def test_abstain_when_required_data_missing(rubric_v1: Any) -> None:
    # declared_scope is required by the scope_compliance criterion
    s = eval_of(rubric_v1, make_case(declared=()))
    assert s.score is None
    assert s.applicability == "abstained:missing data for criteria scope_compliance"
    by_id = {r.criterion_id: r for r in s.criteria_results}
    assert by_id["scope_compliance"].score is None
    assert by_id["completeness"].score == 100  # scored criteria still recorded


def test_abstain_on_empty_workflows(rubric_v1: Any) -> None:
    case = make_case(n=0)
    s = eval_of(rubric_v1, case)
    assert s.score is None and "no workflow records" in s.applicability


def test_abstain_when_sample_below_rubric_policy() -> None:
    shipped = rubric_from_dict(_good_rubric_dict())
    stricter = rubric_from_dict(
        {
            **_good_rubric_dict(),
            "uncertainty": {
                "min_sample_size": 3,
                "abstain_rule": "abstain_score_if_sample_below_min",
            },
        }
    )
    s = eval_of(stricter, make_case(n=2))
    assert s.score is None and "min_sample_size 3" in s.applicability
    # the shipped rubric (min 2) does not abstain on the same input
    assert eval_of(shipped, make_case(n=2)).score is not None


def test_unknown_criterion_forces_abstain(rubric_v1: Any) -> None:
    data = _good_rubric_dict()
    data["criteria"][0]["weight"] = 0.35
    data["criteria"][1]["weight"] = 0.35
    data["criteria"][2]["weight"] = 0.25
    data["criteria"].append({"id": "poetics", "weight": 0.05, "description": "x"})
    stricter = rubric_from_dict(data)
    s = eval_of(stricter, make_case())
    assert s.score is None and "poetics" in s.applicability


def test_uncertainty_bands() -> None:
    assert _uncertainty(1, 2) == "high"
    assert _uncertainty(2, 2) == "medium"
    assert _uncertainty(4, 2) == "low"


# ------------------------------------------------------------ determinism ----


def test_scoring_is_deterministic_across_runs(rubric_v1: Any) -> None:
    case = make_case(n=3, evidence=False, tools=("shell", "browser"))
    a = eval_of(rubric_v1, case)
    b = eval_of(rubric_v1, case)
    assert a == b


def test_partial_scoring_math(rubric_v1: Any) -> None:
    case = make_case(n=2, evidence=False)  # evidence_support -> 0, others 100
    s = eval_of(rubric_v1, case)
    assert s.score == int(0.40 * 100 + 0.35 * 0 + 0.25 * 100)
    by_id = {r.criterion_id: r.score for r in s.criteria_results}
    assert by_id == {"completeness": 100, "evidence_support": 0, "scope_compliance": 100}


def test_injected_clock_is_respected(rubric_v1: Any) -> None:
    late = dt.datetime(2030, 1, 1, tzinfo=dt.UTC)
    s = evaluate(rubric_v1, make_case(), at=late)
    assert s.evaluated_at == late
    with pytest.raises(TypeError):
        evaluate(rubric_v1, make_case(), at="tomorrow")  # type: ignore[arg-type]


def test_pct_truncates_not_rounds() -> None:
    assert _pct(1 / 3) == 33


def test_naive_clock_normalised_to_utc(rubric_v1: Any) -> None:
    s = evaluate(rubric_v1, make_case(), at=dt.datetime(2026, 1, 1))
    assert s.evaluated_at.tzinfo == dt.UTC


# ------------------------------------------------------------ attach paths ----


class FakeSpan:
    def __init__(self) -> None:
        self.attrs: dict[str, Any] = {}

    def set_attribute(self, key: str, value: Any) -> None:
        self.attrs[key] = value


def test_attach_span_attributes() -> None:
    s = eval_of(load_rubric(RUBRIC_V1), make_case())
    span = FakeSpan()
    attrs = attach_to_span(s, span)
    assert attrs == {k: v for k, v in span.attrs.items()}
    assert span.attrs["oaa.quality.rubric_version"] == "1"
    assert span.attrs["oaa.quality.score"] == 100
    assert span.attrs["oaa.quality.advisory"] is True
    assert span.attrs["oaa.quality.abstained"] is False
    assert span.attrs["oaa.quality.criterion.completeness.reason"]
    assert not any(k.startswith("http") or "authorization" in k for k in span.attrs)


def test_attach_callback_sink_receives_attributes() -> None:
    s = eval_of(load_rubric(RUBRIC_V1), make_case())
    seen: list[dict] = []
    assert attach_to_callback(s, seen.append) == seen[0]
    assert seen[0]["oaa.quality.rubric_id"] == "qual"


def test_attach_abstained_score_marks_attributes(rubric_v1: Any) -> None:
    s = eval_of(rubric_v1, make_case(scenario_class="sensitive_data"))
    body = to_score_api_body(s)
    assert body["score"] is None and body["abstained"] is True and body["advisory"] is True
    attrs = to_span_attributes(s)
    assert attrs["oaa.quality.score"] == "" and attrs["oaa.quality.abstained"] is True


def test_score_api_body_round_trips_through_json() -> None:
    s = eval_of(load_rubric(RUBRIC_V1), make_case())
    body = to_score_api_body(s)
    again = json.loads(json.dumps(body))
    assert again == body


# ------------------------------------------------------------ guard tests ----

FORBIDDEN_MODULES = {
    "socket",
    "urllib",
    "urllib3",
    "requests",
    "httpx",
    "http.client",
    "ssl",
    "asyncio",
    "subprocess",
    "multiprocessing",
    "ftplib",
    "telnetlib",
    "paramiko",
    "yaml",  # rubric loading lives in tests/demo, never in the hot path
}
FORBIDDEN_ATTR_ROOTS = {"environ", "system", "popen", "open"}
FORBIDDEN_CALL_NAMES = {"eval", "exec", "compile", "__import__", "open", "popen", "system"}


# The guard surface is the *evaluation path*: rubric.py is schema validation
# (its deferred yaml import is the test/demo loading surface); evaluator.py
# and attach.py must carry zero tools/secrets/network.
_GUARDED_FILES = ("evaluator.py", "attach.py")


def _walk_package_sources() -> dict[str, str]:
    return {
        p.name: p.read_text(encoding="utf-8")
        for p in sorted(SRC_PACKAGE.glob("*.py"))
        if p.name in _GUARDED_FILES
    }


def test_evaluator_and_attach_have_no_forbidden_imports() -> None:
    offenders: list[str] = []
    for name, source in _walk_package_sources().items():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    if root in FORBIDDEN_MODULES:
                        offenders.append(f"{name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                root = (node.module or "").split(".")[0]
                if root in FORBIDDEN_MODULES or node.module in FORBIDDEN_MODULES:
                    offenders.append(f"{name}: from {node.module} import ...")
    assert offenders == []


def test_evaluator_never_calls_dangerous_builtins_or_environ() -> None:
    offenders: list[str] = []
    for name, source in _walk_package_sources().items():
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                if node.func.id in FORBIDDEN_CALL_NAMES:
                    offenders.append(f"{name}: call {node.func.id}()")
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in FORBIDDEN_CALL_NAMES:
                    offenders.append(f"{name}: call .{node.func.attr}()")
            elif isinstance(node, ast.Attribute) and node.attr in FORBIDDEN_ATTR_ROOTS:
                offenders.append(f"{name}: attribute access .{node.attr}")
    assert offenders == []


def test_package_sources_contain_no_secret_shaped_strings() -> None:
    pattern = re.compile(r"(?i)(password|secret|api[_-]?key|token)\s*=\s*[\"'][^\"']+[\"']")
    hits = {name: pattern.findall(src) for name, src in _walk_package_sources().items()}
    assert {k: v for k, v in hits.items() if v} == {}


def test_evaluator_runtime_runs_isolated_from_environment_and_files(
    rubric_v1: Any, monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """The evaluator must produce an identical score with env scrubbed and cwd elsewhere."""
    case = make_case(n=2, evidence=False, tools=("shell", "browser"))

    real_env = dict(os.environ)
    monkeypatch.setattr(os, "environ", {}, raising=False)
    monkeypatch.chdir(tmp_path)
    s_isolated = evaluate(rubric_v1, case, at=AT)
    assert s_isolated.score is not None

    monkeypatch.setattr(os, "environ", real_env, raising=False)
    monkeypatch.chdir(REPO_ROOT)
    s_normal = evaluate(rubric_v1, case, at=AT)
    assert s_isolated == s_normal


def test_evaluator_imports_nothing_beyond_stdlib_and_oaa_quality() -> None:
    tree = ast.parse((SRC_PACKAGE / "evaluator.py").read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            roots.add((node.module or "oaa_quality." + "__future__").split(".")[0])
    assert roots <= {"__future__", "datetime", "dataclasses", "typing", "oaa_quality"}
