# SPDX-License-Identifier: Apache-2.0
"""Versioned quality rubrics (QUAL-01).

A rubric is a small, reviewable YAML document (``services/quality/rubrics/*.yaml``)
declaring *what good looks like* for a scenario class: the criteria (each with a
weight and a description), the applicability filter (which scenario classes the
rubric may be applied to) and the uncertainty policy (minimum sample size and
the abstain rule).

Design rules (see ``docs/spikes/QUAL-01-findings.md``):

- rubric identities are versioned pairs ``(rubric_id, rubric_version)``; every
  QualityScore carries both, so scores are always interpretable against an
  immutable rubric revision. Rubric files are never mutated in place — a
  policy change is a new file with a bumped version.
- ``applicable_to`` is a *positive* allow-list: the evaluator abstains when the
  scenario class is not listed (default-deny, never "apply everywhere").
- ``uncertainty`` is explicit policy, not folklore: ``min_sample_size`` bounds
  when a score is low-uncertainty, ``abstain_rule`` names (in prose) when the
  evaluator must refuse to score at all.
- Loading is pure validation: no defaults are invented silently, no weights are
  renormalised behind the reviewer's back. A malformed rubric is an error.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Criterion:
    """One rubric criterion: a weighted, described scoring dimension."""

    id: str
    weight: float
    description: str

    def __post_init__(self) -> None:
        if not self.id or not isinstance(self.id, str):
            raise ValueError("criterion.id must be a non-empty string")
        if not isinstance(self.weight, (int, float)) or isinstance(self.weight, bool):
            raise ValueError(f"criterion {self.id!r}: weight must be a number")
        if not (0.0 < float(self.weight) <= 1.0):
            raise ValueError(f"criterion {self.id!r}: weight must be in (0, 1]")
        if not self.description or not isinstance(self.description, str):
            raise ValueError(f"criterion {self.id!r}: description must be a non-empty string")


@dataclass(frozen=True)
class Applicability:
    """Positive allow-list of scenario classes this rubric may score."""

    scenario_classes: frozenset[str]

    def __post_init__(self) -> None:
        if not self.scenario_classes:
            raise ValueError(
                "applicable_to.scenario_classes must be a non-empty allow-list "
                "(a rubric that applies to nothing exists, a rubric that applies "
                "to everything is an enforceable claim we do not make)"
            )
        object.__setattr__(
            self, "scenario_classes", frozenset(str(c) for c in self.scenario_classes)
        )

    def covers(self, scenario_class: str) -> bool:
        return scenario_class in self.scenario_classes


@dataclass(frozen=True)
class UncertaintyPolicy:
    """Rubric-level uncertainty policy.

    ``min_sample_size`` is the number of scored units (e.g. workflows) below
    which the evaluator may never claim low uncertainty; ``abstain_rule`` is a
    prose statement of when the evaluator must abstain entirely (it is carried
    verbatim into findings, it is not machine-parsed).
    """

    min_sample_size: int
    abstain_rule: str

    def __post_init__(self) -> None:
        if not isinstance(self.min_sample_size, int) or isinstance(self.min_sample_size, bool):
            raise ValueError("uncertainty.min_sample_size must be an int")
        if self.min_sample_size < 1:
            raise ValueError("uncertainty.min_sample_size must be >= 1")
        if not self.abstain_rule or not isinstance(self.abstain_rule, str):
            raise ValueError("uncertainty.abstain_rule must be a non-empty prose string")


@dataclass(frozen=True)
class Rubric:
    """A versioned quality rubric: criteria + applicability + uncertainty policy."""

    rubric_id: str
    rubric_version: str
    criteria: tuple[Criterion, ...]
    applicable_to: Applicability
    uncertainty: UncertaintyPolicy

    def __post_init__(self) -> None:
        if not self.rubric_id or not isinstance(self.rubric_id, str):
            raise ValueError("rubric_id must be a non-empty string")
        if not self.rubric_version or not isinstance(self.rubric_version, str):
            raise ValueError("rubric_version must be a non-empty string")
        if not self.criteria or not all(isinstance(c, Criterion) for c in self.criteria):
            raise ValueError("rubric needs at least one criterion")
        weights = [float(c.weight) for c in self.criteria]
        if abs(sum(weights) - 1.0) > 1e-6:
            raise ValueError(f"rubric criterion weights must sum to 1.0 (got {sum(weights):.6f})")
        ids = [c.id for c in self.criteria]
        if len(set(ids)) != len(ids):
            raise ValueError(f"criterion ids must be unique: {ids}")
        object.__setattr__(self, "criteria", tuple(sorted(self.criteria, key=lambda c: c.id)))

    @property
    def criterion_ids(self) -> tuple[str, ...]:
        return tuple(c.id for c in self.criteria)


def rubric_from_dict(data: object) -> Rubric:
    """Validate an already-parsed YAML/JSON mapping into a Rubric.

    Raises ``ValueError`` (with the offending field named) on any schema
    violation. Nothing is defaulted: every field is required.
    """
    if not isinstance(data, dict):
        raise ValueError("rubric document must be a mapping")
    for key in ("rubric_id", "rubric_version", "criteria", "applicable_to", "uncertainty"):
        if key not in data:
            raise ValueError(f"rubric field {key!r} is required (no defaults)")
    criteria: list[Criterion] = []
    raw_criteria = data["criteria"]
    if not isinstance(raw_criteria, list) or not raw_criteria:
        raise ValueError("criteria must be a non-empty list")
    for i, raw in enumerate(raw_criteria):
        if not isinstance(raw, dict):
            raise ValueError(f"criteria[{i}] must be a mapping")
        for key in ("id", "weight", "description"):
            if key not in raw:
                raise ValueError(f"criteria[{i}].{key} is required")
        criteria.append(
            Criterion(
                id=str(raw["id"]),
                weight=raw["weight"],
                description=str(raw["description"]),
            )
        )
    raw_app = data["applicable_to"]
    if not isinstance(raw_app, dict) or "scenario_classes" not in raw_app:
        raise ValueError("applicable_to must be a mapping with scenario_classes")
    raw_unc = data["uncertainty"]
    if not isinstance(raw_unc, dict):
        raise ValueError("uncertainty must be a mapping")
    for key in ("min_sample_size", "abstain_rule"):
        if key not in raw_unc:
            raise ValueError(f"uncertainty.{key} is required")
    return Rubric(
        rubric_id=str(data["rubric_id"]),
        rubric_version=str(data["rubric_version"]),
        criteria=tuple(criteria),
        applicable_to=Applicability(frozenset(raw_app["scenario_classes"])),
        uncertainty=UncertaintyPolicy(
            min_sample_size=raw_unc["min_sample_size"],
            abstain_rule=str(raw_unc["abstain_rule"]),
        ),
    )


def load_rubric(path: Path) -> Rubric:
    """Load a rubric YAML file. Read-only, requires PyYAML (test/demo surface)."""
    import yaml  # noqa: PLC0415  # lazy optional dep: keep the runtime package stdlib-only

    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    return rubric_from_dict(raw)


__all__ = [
    "Applicability",
    "Criterion",
    "Rubric",
    "UncertaintyPolicy",
    "load_rubric",
    "rubric_from_dict",
]
