# SPDX-License-Identifier: Apache-2.0
"""oaa_rules — RULE-01 deterministic security rules engine (SEC-001..011)."""

from .core import (
    ALL_RULES,
    CONFIDENCES,
    CORRELATED_RECEIPT_STATES,
    EVENT_KINDS,
    SEVERITIES,
    Event,
    Finding,
    Rule,
    RulesConfig,
    Suppression,
    load_config,
    run_rules,
)

__all__ = [
    "ALL_RULES",
    "CONFIDENCES",
    "CORRELATED_RECEIPT_STATES",
    "EVENT_KINDS",
    "SEVERITIES",
    "Event",
    "Finding",
    "Rule",
    "RulesConfig",
    "Suppression",
    "load_config",
    "run_rules",
]
