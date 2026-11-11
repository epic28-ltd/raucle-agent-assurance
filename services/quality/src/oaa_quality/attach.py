"""Attach an advisory QualityScore (QUAL-01) to observability surfaces.

Two equivalent sinks, both *callback style* — the module never owns a span,
an HTTP client or a process:

1. **OTel span attributes** — ``to_span_attributes`` renders the score as
   ``oaa.quality.*`` attributes and ``attach_to_span`` sets them on an already
   constructed span (duck-typed: any object with ``set_attribute``). The OTel
   SDK is NOT imported here, so the package stays stdlib-only and network-free.
2. **investigation-ui score-API body** — ``to_score_api_body`` renders the
   advisory payload the console would POST to the (future) score endpoint.

Both are pure renderers plus a callback hook; enforcement and delivery
scheduling belong to the caller. See ``docs/spikes/QUAL-01-findings.md``
for the sink-pattern comparison and the "no auto-enforcement" rule.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from oaa_quality.evaluator import QualityScore

ATTR_PREFIX = "oaa.quality."

# callback-style sink: receives the rendered attribute dictionary
SpanSink = Callable[[dict[str, Any]], None]


def to_span_attributes(score: QualityScore) -> dict[str, Any]:
    """Render a QualityScore as ``oaa.quality.*`` span attributes.

    Values are OTel-attribute-safe scalars only (str/int/bool). Timestamps are
    ISO-8601 strings; criteria are flattened to one attribute per criterion id.
    """
    attrs: dict[str, Any] = {
        f"{ATTR_PREFIX}rubric_id": score.rubric_id,
        f"{ATTR_PREFIX}rubric_version": score.rubric_version,
        f"{ATTR_PREFIX}advisory": True,
        f"{ATTR_PREFIX}reviewer_status": score.reviewer_status,
        f"{ATTR_PREFIX}applicability": score.applicability,
        f"{ATTR_PREFIX}uncertainty": score.uncertainty,
        f"{ATTR_PREFIX}evaluated_ref": score.evaluated_ref,
        f"{ATTR_PREFIX}evaluated_at": score.evaluated_at.isoformat(),
    }
    if score.score is None:
        attrs[f"{ATTR_PREFIX}score"] = ""
        attrs[f"{ATTR_PREFIX}abstained"] = True
    else:
        attrs[f"{ATTR_PREFIX}score"] = int(score.score)
        attrs[f"{ATTR_PREFIX}abstained"] = False
    for res in score.criteria_results:
        key = f"{ATTR_PREFIX}criterion.{res.criterion_id}"
        attrs[key] = "" if res.score is None else int(res.score)
        attrs[f"{key}.reason"] = res.reason
    return attrs


def attach_to_span(score: QualityScore, span: Any) -> dict[str, Any]:
    """Attach the score to an existing span via ``span.set_attribute``.

    Duck-typed callback style: the span object is provided by the caller, this
    module imports nothing from the OTel SDK and opens nothing.
    """
    attrs = to_span_attributes(score)
    for key, value in attrs.items():
        span.set_attribute(key, value)
    return attrs


def attach_to_callback(score: QualityScore, sink: SpanSink) -> dict[str, Any]:
    """Render and hand the attribute dict to a caller-supplied sink callback."""
    attrs = to_span_attributes(score)
    sink(attrs)
    return attrs


def to_score_api_body(score: QualityScore) -> dict[str, Any]:
    """Render the JSON body for the investigation-ui score API (advisory POST).

    The endpoint is proposed-but-not-built (findings §attach surface); this is
    the contract so both sides can be reviewed before wiring.
    """
    return {
        "advisory": True,
        "rubric_id": score.rubric_id,
        "rubric_version": score.rubric_version,
        "score": score.score,
        "abstained": score.score is None,
        "uncertainty": score.uncertainty,
        "applicability": score.applicability,
        "reviewer_status": score.reviewer_status,
        "evaluated_ref": score.evaluated_ref,
        "evaluated_at": score.evaluated_at.isoformat(),
        "criteria": [
            {
                "id": res.criterion_id,
                "score": res.score,
                "reason": res.reason,
            }
            for res in score.criteria_results
        ],
    }


__all__ = [
    "ATTR_PREFIX",
    "SpanSink",
    "attach_to_callback",
    "attach_to_span",
    "to_score_api_body",
    "to_span_attributes",
]
