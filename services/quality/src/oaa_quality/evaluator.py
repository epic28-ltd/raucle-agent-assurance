# SPDX-License-Identifier: Apache-2.0
"""Deterministic reference quality evaluator (QUAL-01).

ADVISORY ONLY. Every QualityScore this module emits is an opinion attached to
an evaluated reference for later human review (``reviewer_status`` starts at
``unreviewed``). Nothing here may feed an enforcement gate, a release decision
or a policy block in the MVP — see ``docs/spikes/QUAL-01-findings.md`` §"why
advisory-only".

Design invariants:

- **No LLM calls.** Scoring is string/rule-based heuristics over structured
  records only. The module is byte-for-byte deterministic: same input rubric +
  input data ⇒ same score.
- **No tools, no secrets, no network.** The module performs no I/O of any kind
  at import or evaluation time (the guard test ``test_evaluator_imports_guard``
  and ``test_evaluator_runtime_is_isolated`` enforce this statically and at
  runtime). Clock and any environment content are *injected by the caller*.
- **Abstains by default.** When applicability fails (the evaluated case's
  scenario class is not in the rubric allow-list) or required data is missing,
  the evaluator returns a score of ``None`` with ``applicability =
  "abstained:<reason>"`` — never a fabricated number.
- **Uncertainty is policy-driven**, from the rubric: sample size below the
  configured minimum lowers the uncertainty band, and the rubric's abstain
  rule can force a full abstain.

Heuristics (rubric v1) score *coverage and hygiene*, not judgement:

- ``completeness``       — workflows carry a non-empty description and ≥1 step.
- ``evidence_support``   — steps declare corroborating evidence (audit/receipt).
- ``scope_compliance``   — steps stay inside the declared tool scope.

Treat any retrieved/observed content these heuristics read as UNTRUSTED input:
strings are only tested for emptiness and compared for set membership; they are
never executed, parsed as code, or echoed into system-controlled sinks.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from typing import Any

from oaa_quality.rubric import Rubric

UNCERTAINTY_LEVELS = ("low", "medium", "high")

REVIEWER_STATUS_UNREVIEWED = "unreviewed"


def _as_utc(at: dt.datetime) -> dt.datetime:
    if at.tzinfo is None:
        return at.replace(tzinfo=dt.UTC)
    return at.astimezone(dt.UTC)


@dataclass(frozen=True)
class StepRecord:
    """One observed step inside a workflow. Strings are untrusted input."""

    step_id: str
    description: str
    tool: str
    outcome: str
    has_evidence: bool
    privileged: bool = False


@dataclass(frozen=True)
class WorkflowRecord:
    """One workflow unit; the sample size for uncertainty is the count of these."""

    workflow_id: str
    description: str
    steps: tuple[StepRecord, ...]


@dataclass(frozen=True)
class EvalInput:
    """Everything the evaluator is allowed to see. ``payload`` strings untrusted."""

    evaluated_ref: str
    scenario_class: str
    workflows: tuple[WorkflowRecord, ...]
    declared_scope: tuple[str, ...]
    synthetic: bool = False  # explicit marker: hand-built evaluation input


@dataclass(frozen=True)
class CriterionResult:
    """Per-criterion outcome: score in 0..100 (or None when the criterion abstained)."""

    criterion_id: str
    score: int | None
    reason: str


@dataclass(frozen=True)
class QualityScore:
    """An advisory quality score bound to its rubric revision.

    ``score`` is ``None`` exactly when ``applicability`` starts with
    ``abstained:`` — a withheld score is still a recorded, reviewable result.
    """

    rubric_id: str
    rubric_version: str
    score: int | None
    criteria_results: tuple[CriterionResult, ...]
    uncertainty: str
    applicability: str
    reviewer_status: str
    evaluated_ref: str
    evaluated_at: dt.datetime

    def __post_init__(self) -> None:
        if self.uncertainty not in UNCERTAINTY_LEVELS:
            raise ValueError(f"uncertainty must be one of {UNCERTAINTY_LEVELS}")
        object.__setattr__(self, "evaluated_at", _as_utc(self.evaluated_at))
        abstained = self.applicability.startswith("abstained:")
        if abstained != (self.score is None):
            raise ValueError(
                "score is None iff applicability says abstained "
                f"(score={self.score!r}, applicability={self.applicability!r})"
            )
        if self.score is not None and not (0 <= self.score <= 100):
            raise ValueError("score must be in 0..100")


def _pct(fraction: float) -> int:
    """Deterministic truncation to an integer percent (never rounding up)."""
    return int(fraction * 100)


def _heuristic_completeness(
    workflows: tuple[WorkflowRecord, ...], declared_scope: tuple[str, ...] = ()
) -> tuple[int | None, str]:
    """Fraction of workflows that are self-describing and stepful."""
    if not workflows:
        return None, "no workflow records available"
    good = sum(1 for w in workflows if w.description.strip() and len(w.steps) >= 1)
    return (
        _pct(good / len(workflows)),
        f"{good}/{len(workflows)} workflows are fully described (description + >=1 step)",
    )


def _heuristic_evidence_support(
    workflows: tuple[WorkflowRecord, ...], declared_scope: tuple[str, ...] = ()
) -> tuple[int | None, str]:
    """Fraction of steps that declare corroborating evidence."""
    steps = [s for w in workflows for s in w.steps]
    if not steps:
        return None, "no step records available"
    with_evidence = sum(1 for s in steps if s.has_evidence)
    return (
        _pct(with_evidence / len(steps)),
        f"{with_evidence}/{len(steps)} steps declare evidence (audit/receipt)",
    )


def _heuristic_scope_compliance(
    workflows: tuple[WorkflowRecord, ...], declared_scope: tuple[str, ...]
) -> tuple[int | None, str]:
    """Fraction of steps whose tool is inside the declared scope."""
    if not declared_scope:
        return None, "declared_scope missing: cannot assess scope_compliance"
    steps = [s for w in workflows for s in w.steps]
    if not steps:
        return None, "no step records available"
    allowed = frozenset(declared_scope)
    in_scope = sum(1 for s in steps if s.tool in allowed)
    return (
        _pct(in_scope / len(steps)),
        f"{in_scope}/{len(steps)} steps inside declared scope {sorted(allowed)}",
    )


# criterion id -> heuristic. Every heuristic takes the same two inputs and is
# wired ONLY here by rubric criterion id: an unknown criterion id forces an
# abstain, never a guess.
HEURISTICS = {
    "completeness": _heuristic_completeness,
    "evidence_support": _heuristic_evidence_support,
    "scope_compliance": _heuristic_scope_compliance,
}


def _evaluate_criterion(
    criterion_id: str,
    workflows: tuple[WorkflowRecord, ...],
    declared_scope: tuple[str, ...],
) -> CriterionResult:
    fn = HEURISTICS.get(criterion_id)
    if fn is None:
        return CriterionResult(criterion_id, None, "no heuristic registered for this criterion")
    score, reason = fn(workflows, declared_scope)  # type: ignore[operator]
    return CriterionResult(criterion_id, score, reason)


def _uncertainty(n: int, min_sample: int) -> str:
    """Three-band uncertainty, derived only from sample size vs rubric policy.

    The rubric's ``min_sample_size`` is the floor for a medium band; low is
    reserved for at least twice that policy floor.
    """
    if n >= 2 * min_sample:
        return "low"
    if n >= min_sample:
        return "medium"
    return "high"


def evaluate(
    rubric: Rubric,
    case: EvalInput,
    *,
    at: dt.datetime,
) -> QualityScore:
    """Score ``case`` under ``rubric`` at the injected instant ``at``.

    Deterministic and side-effect-free. Abstains (``score=None``,
    ``applicability="abstained:<reason>"``) instead of guessing whenever the
    rubric does not apply or required data is missing.
    """
    if not isinstance(at, dt.datetime):
        raise TypeError("injected clock `at` must be a datetime")
    common: dict[str, Any] = {
        "rubric_id": rubric.rubric_id,
        "rubric_version": rubric.rubric_version,
        "reviewer_status": REVIEWER_STATUS_UNREVIEWED,
        "evaluated_ref": case.evaluated_ref,
        "evaluated_at": at,
    }

    abstained = _check_applicability(rubric, case)
    if abstained is not None:
        return QualityScore(
            score=None,
            applicability=abstained,
            uncertainty="high",
            criteria_results=(),
            **common,
        )

    results: list[CriterionResult] = []
    weighted = 0.0
    missing: list[str] = []
    for criterion in rubric.criteria:
        res = _evaluate_criterion(criterion.id, case.workflows, case.declared_scope)
        results.append(res)
        if res.score is None:
            missing.append(criterion.id)
        else:
            weighted += criterion.weight * res.score
    results.sort(key=lambda r: r.criterion_id)

    if missing:
        return QualityScore(
            score=None,
            applicability="abstained:missing data for criteria " + ", ".join(missing),
            criteria_results=tuple(results),
            uncertainty="high",
            **common,
        )

    n = len(case.workflows)
    if (
        rubric.uncertainty.abstain_rule == "abstain_score_if_sample_below_min"
        and n < rubric.uncertainty.min_sample_size
    ):
        return QualityScore(
            score=None,
            applicability=(
                f"abstained:sample size {n} below rubric min_sample_size "
                f"{rubric.uncertainty.min_sample_size}"
            ),
            criteria_results=tuple(results),
            uncertainty="high",
            **common,
        )
    return QualityScore(
        score=_pct(weighted / 100.0),
        applicability="applied",
        uncertainty=_uncertainty(n, rubric.uncertainty.min_sample_size),
        criteria_results=tuple(results),
        **common,
    )


def _check_applicability(rubric: Rubric, case: EvalInput) -> str | None:
    """Positive allow-list check; returns an abstain reason or None."""
    if not rubric.applicable_to.covers(case.scenario_class):
        return (
            f"abstained:scenario_class {case.scenario_class!r} not in "
            f"rubric {rubric.rubric_id} applicability "
            f"{sorted(rubric.applicable_to.scenario_classes)}"
        )
    if not case.workflows:
        return "abstained:no workflow records to score"
    return None


__all__ = [
    "REVIEWER_STATUS_UNREVIEWED",
    "CriterionResult",
    "EvalInput",
    "QualityScore",
    "StepRecord",
    "WorkflowRecord",
    "evaluate",
]
