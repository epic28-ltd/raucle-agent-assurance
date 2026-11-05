# SPDX-License-Identifier: Apache-2.0
"""Loader for the OV-11 scenario taxonomy.

Pure stdlib: reads schemas/scenario-taxonomy/taxonomy.json and exposes
validation. The consistency tests are the validator; load_taxonomy is strict so
that no malformed taxonomy can be silently consumed downstream.
"""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TAXONOMY_PATH = REPO / "schemas" / "scenario-taxonomy" / "taxonomy.json"
RED_RULE_LABELS_PATH = REPO / "tests" / "taxonomy" / "fixtures" / "red_rule_labels.json"

EXPECTED_OPENAGENTSAFETY_CATEGORIES = (
    "Computer security compromise",
    "Data loss / corruption",
    "Privacy breach",
    "Unsafe code execution",
    "Financial loss",
    "Spreading malicious content",
    "Legal violations",
    "Harmful decision-making",
)

EXPECTED_CAGE_1_DIMENSIONS = (
    "Identity and Authority",
    "Policy Enforcement",
    "Retrieval Trust",
    "Memory Integrity",
    "Tool Safety",
    "Planning Control",
    "Human Oversight",
    "Audit and Replayability",
    "Conflict and Boundary Handling",
    "Failure Behavior",
    "Operational Readiness",
    "Business Fitness",
)


def load_taxonomy() -> dict:
    return json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))


def load_committed_red_labels() -> dict[str, str]:
    return json.loads(RED_RULE_LABELS_PATH.read_text(encoding="utf-8"))


def red_rule_refs(taxonomy: dict) -> list[str]:
    refs = []
    for row in taxonomy["rows"]:
        refs.extend(r for r in row.get("primitive_refs", []) if r.startswith("RED-"))
    return refs
