"""Open Agent Assurance — optional quality scoring (QUAL-01).

Advisory-only quality scores produced by a deterministic reference evaluator
under versioned rubrics. No enforcement coupling, no LLM calls, no tools,
no secrets, no network; the clock is always caller-injected.
"""
# SPDX-License-Identifier: FSL-1.1-ALv2

from oaa_quality.attach import (
    attach_to_callback,
    attach_to_span,
    to_score_api_body,
    to_span_attributes,
)
from oaa_quality.evaluator import (
    CriterionResult,
    EvalInput,
    QualityScore,
    StepRecord,
    WorkflowRecord,
    evaluate,
)
from oaa_quality.rubric import (
    Applicability,
    Criterion,
    Rubric,
    UncertaintyPolicy,
    load_rubric,
    rubric_from_dict,
)

__all__ = [
    "Applicability",
    "Criterion",
    "CriterionResult",
    "EvalInput",
    "QualityScore",
    "Rubric",
    "StepRecord",
    "UncertaintyPolicy",
    "WorkflowRecord",
    "attach_to_callback",
    "attach_to_span",
    "evaluate",
    "load_rubric",
    "rubric_from_dict",
    "to_score_api_body",
    "to_span_attributes",
]
__version__ = "0.0.1.dev0"
