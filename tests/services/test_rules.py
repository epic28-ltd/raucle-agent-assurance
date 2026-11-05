# SPDX-License-Identifier: Apache-2.0
"""RULE-01 deterministic security rules engine tests (raucle-free).

Everything is synthetic index-plane records: hand-built Event rows with an
explicit ``synthetic: True`` marker, fake refs and fake hashes. No canonical
receipt bytes, no raucle imports. Table-driven: one positive, one negative
(and where relevant, a suppression case) fixture per rule.
"""

from __future__ import annotations

import datetime as dt
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "services" / "rules" / "src"))

from oaa_rules import (
    ALL_RULES,
    CONFIDENCES,
    CORRELATED_RECEIPT_STATES,
    EVENT_KINDS,
    SEVERITIES,
    Event,
    RulesConfig,
    Suppression,
    load_config,
    run_rules,
)

T0 = dt.datetime(2026, 11, 4, 12, 0, 0, tzinfo=dt.UTC)
SECRET = "AKIAXXXXXXXXXXXXXXXX"  # matches aws_access_key pattern in shipped config
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def ev(kind: str, ref: str | None = None, mins: float = 0, **kw) -> Event:
    """Synthetic index-plane record (test-only)."""
    return Event(kind=kind, at=T0 + dt.timedelta(minutes=mins), ref=ref, **kw)


def _corr_event(state: str, trace_id: str, decision: str = "allow", **kw) -> Event:
    return ev("correlation", state=state, trace_id=trace_id, decision=decision, **kw)


# ------------------------------------------------------------- test tables --

# (rule_id, name, events, config kwargs, expected finding count, subject)
CASES: list[tuple[str, str, list[Event], dict, int, str | None]] = [
    # SEC-001 ------------------------------------------------------------
    (
        "SEC-001",
        "positive-receipt-missing-privileged",
        [_corr_event("receipt_missing", "t1", tool="shell")],
        {},
        1,
        "shell",
    ),
    (
        "SEC-001",
        "negative-late-arrival-is-corroborated",
        [_corr_event("late_arrival", "t1", tool="shell")],
        {},
        0,
        None,
    ),
    (
        "SEC-001",
        "negative-tool-not-privileged",
        [_corr_event("receipt_missing", "t1", tool="calculator")],
        {},
        0,
        None,
    ),
    # SEC-002 ------------------------------------------------------------
    (
        "SEC-002",
        "positive-invalid",
        [ev("verification", ref="r1", state="invalid", receipt_hash="sha256:0" + "0" * 63)],
        {},
        1,
        None,
    ),
    (
        "SEC-002",
        "positive-unsupported-schema",
        [ev("verification", ref="r2", state="unsupported_schema")],
        {},
        1,
        None,
    ),
    (
        "SEC-002",
        "negative-unknown-key-is-coverage-gap-not-failure",
        [
            ev("verification", ref="r3", state="unknown_key"),
            ev("verification", ref="r4", state="valid"),
        ],
        {},
        0,
        None,
    ),
    # SEC-003 ------------------------------------------------------------
    (
        "SEC-003",
        "positive-denial-rate-over-threshold",
        [
            ev(
                "tool_audit",
                ref=f"d{i}",
                mins=i,
                application="app-a",
                decision="deny" if i < 3 else "allow",
                outcome="success",
            )
            for i in range(6)
        ],
        {},
        1,
        "app-a",
    ),
    (
        "SEC-003",
        "negative-denial-rate-below-threshold",
        [
            ev(
                "tool_audit",
                ref=f"d{i}",
                mins=i,
                application="app-b",
                decision="deny" if i == 0 else "allow",
                outcome="success",
            )
            for i in range(6)
        ],
        {},
        0,
        None,
    ),
    (
        "SEC-003",
        "negative-too-few-samples",
        [
            ev(
                "tool_audit",
                ref=f"d{i}",
                mins=i,
                application="app-c",
                decision="deny",
                outcome="success",
            )
            for i in range(3)
        ],
        {},
        0,
        None,
    ),
    # SEC-004 ------------------------------------------------------------
    (
        "SEC-004",
        "positive-success-after-correlated-deny",
        [
            _corr_event("matched", "t1", decision="deny"),
            ev("tool_audit", ref="a1", outcome="success", trace_id="t1", tool="shell"),
        ],
        {},
        1,
        "shell",
    ),
    (
        "SEC-004",
        "negative-success-after-allow",
        [
            _corr_event("matched", "t1", decision="allow"),
            ev("tool_audit", ref="a2", outcome="success", trace_id="t1", tool="shell"),
        ],
        {},
        0,
        None,
    ),
    (
        "SEC-004",
        "negative-tool-side-failure-not-success",
        [
            _corr_event("matched", "t1", decision="deny"),
            ev("tool_audit", ref="a3", outcome="failure", trace_id="t1", tool="shell"),
        ],
        {},
        0,
        None,
    ),
    # SEC-005 ------------------------------------------------------------
    (
        "SEC-005",
        "positive-cycle-over-bound",
        [
            ev(
                "tool_audit",
                ref=f"c{i}",
                mins=i / 2,
                agent_id="a1",
                tool="shell",
                outcome="success",
            )
            for i in range(21)
        ],
        {},
        1,
        "a1/shell",
    ),
    (
        "SEC-005",
        "negative-cycle-at-bound",
        [
            ev(
                "tool_audit",
                ref=f"c{i}",
                mins=i / 2,
                agent_id="a1",
                tool="shell",
                outcome="success",
            )
            for i in range(20)
        ],
        {},
        0,
        None,
    ),
    (
        "SEC-005",
        "negative-calls-outside-window",
        [
            ev(
                "tool_audit",
                ref=f"c{i}",
                mins=i * 61,
                agent_id="a1",
                tool="shell",
                outcome="success",
            )
            for i in range(25)
        ],
        {},
        0,
        None,
    ),
    # SEC-006 ------------------------------------------------------------
    (
        "SEC-006",
        "positive-new-privileged-tool-off-baseline",
        [ev("tool_audit", ref="rel1", tool="http_fetch", release_id="rel-2026.11")],
        {"tool_baseline": {"rel-2026.11": frozenset({"shell"})}},
        1,
        "rel-2026.11",
    ),
    (
        "SEC-006",
        "negative-tool-in-baseline",
        [ev("tool_audit", ref="rel2", tool="shell", release_id="rel-2026.11")],
        {"tool_baseline": {"rel-2026.11": frozenset({"shell"})}},
        0,
        None,
    ),
    (
        "SEC-006",
        "negative-release-has-no-baseline-entry",
        [ev("tool_audit", ref="rel3", tool="http_fetch", release_id="rel-new")],
        {"tool_baseline": {"rel-2026.11": frozenset({"shell"})}},
        0,
        None,
    ),
    # SEC-007 ------------------------------------------------------------
    (
        "SEC-007",
        "positive-backlog-over-threshold",
        [ev("verification", ref=f"v{i}", state="unavailable") for i in range(4)]
        + [
            ev("verification", ref="vok", state="valid"),
            ev("ingest", ref="i1", state="unavailable"),
        ],
        {},
        1,
        None,
    ),
    (
        "SEC-007",
        "negative-backlog-below-threshold",
        [
            ev("verification", ref="vok1", state="valid"),
            ev("verification", ref="v0", state="unavailable"),
        ],
        {},
        0,
        None,
    ),
    (
        "SEC-007",
        "negative-too-few-coverage-events",
        [ev("verification", ref=f"u{i}", state="unavailable") for i in range(3)],
        {},
        0,
        None,
    ),
    # SEC-008 ------------------------------------------------------------
    (
        "SEC-008",
        "positive-credential-pattern-in-index",
        [ev("ingest", ref="s1", agent_id="a1", content=f"env import {SECRET}")],
        {"patterns": {"aws_access_key": SECRET.replace("X", "[0-9A-Z]")}},
        1,
        "a1",
    ),
    (
        "SEC-008",
        "negative-benign-index-content",
        [ev("ingest", ref="s2", content="plain workflow narrative text")],
        {"patterns": {"aws_access_key": SECRET.replace("X", "[0-9A-Z]")}},
        0,
        None,
    ),
    # SEC-009 (bypass, ADR-0004) -----------------------------------------
    (
        "SEC-009",
        "positive-privileged-execution-no-receipt",
        [
            ev(
                "tool_audit",
                ref="b1",
                tool="shell",
                privileged=True,
                trace_id="t9",
                outcome="success",
            ),
            _corr_event("matched", "t-other"),  # receipt exists elsewhere only
        ],
        {},
        1,
        "shell",
    ),
    (
        "SEC-009",
        "positive-unkeyed-privileged-execution",
        [ev("tool_audit", ref="b2", tool="shell", privileged=True, trace_id=None)],
        {},
        1,
        None,
    ),
    (
        "SEC-009",
        "negative-privileged-execution-corroborated",
        [
            ev(
                "tool_audit",
                ref="b3",
                tool="shell",
                privileged=True,
                trace_id="t1",
                outcome="success",
            ),
            _corr_event("late_arrival", "t1"),  # receipt exists (late but real)
        ],
        {},
        0,
        None,
    ),
    (
        "SEC-009",
        "negative-tool-not-privileged",
        [ev("tool_audit", ref="b4", tool="calculator", privileged=False, trace_id="t9")],
        {},
        0,
        None,
    ),
    (
        "SEC-009",
        "negative-evidence-gap-is-not-bypass",
        # nothing executed on any vantage — an evidence gap, never a finding
        [
            ev("ingest", ref="g1", state="unavailable"),
            ev("correlation", ref="g2", state="trace_missing", trace_id=None),
        ],
        {},
        0,
        None,
    ),
    (
        "SEC-009",
        "negative-trace-only-signal-never-corroborates",
        # trace-side telemetry alone must NEVER corroborate a privileged call
        [
            ev(
                "tool_audit",
                ref="b5",
                tool="shell",
                privileged=True,
                trace_id="t1",
                outcome="success",
            ),
            ev(
                "ingest",
                ref="t-only",
                trace_id="t1",
                content="trace narrative claims receipt was raised",
            ),  # T vantage
        ],
        {},
        1,  # still fires — T-only never suppresses the discrepancy
        "shell",
    ),
    # SEC-010 (custody, ADR-0004) ----------------------------------------
    (
        "SEC-010",
        "positive-credential-use-no-lease",
        [
            ev(
                "custody",
                ref="l1",
                action="use",
                credential_id="cred-1",
                tool="shell",
                agent_id="a1",
            ),
        ],
        {"custody_covered_tools": frozenset({"shell"})},
        1,
        "a1",
    ),
    (
        "SEC-010",
        "negative-matching-lease-issued",
        [
            ev("custody", ref="l2", action="lease_issued", credential_id="cred-2", tool="shell"),
            ev(
                "custody",
                ref="l3",
                action="use",
                credential_id="cred-2",
                tool="shell",
                agent_id="a1",
            ),
        ],
        {"custody_covered_tools": frozenset({"shell"})},
        0,
        None,
    ),
    (
        "SEC-010",
        "negative-tool-not-in-custody-coverage-map",
        [
            ev(
                "custody",
                ref="l4",
                action="use",
                credential_id="cred-3",
                tool="http_fetch",
                agent_id="a1",
            ),
        ],
        {"custody_covered_tools": frozenset({"shell"})},
        0,
        None,
    ),
    (
        "SEC-010",
        "negative-no-custody-data-at-all",
        [ev("verification", ref="l5", state="valid")],
        {"custody_covered_tools": frozenset({"shell"})},
        0,
        None,
    ),
    # SEC-011 ------------------------------------------------------------
    (
        "SEC-011",
        "positive-mid-chain-identity-change",
        [
            ev(
                "identity",
                ref="p1",
                agent_id="a1",
                chain_seq=1,
                producer_id="prod-a",
                authenticated=True,
            ),
            ev(
                "identity",
                ref="p2",
                agent_id="a1",
                chain_seq=2,
                producer_id="prod-a",
                authenticated=True,
            ),
            ev(
                "identity",
                ref="p3",
                agent_id="a1",
                chain_seq=3,
                producer_id="prod-b",
                authenticated=True,
            ),
        ],
        {},
        1,
        "a1",
    ),
    (
        "SEC-011",
        "negative-stable-producer-identity",
        [
            ev(
                "identity",
                ref="p4",
                agent_id="a1",
                chain_seq=1,
                producer_id="prod-a",
                authenticated=True,
            ),
            ev(
                "identity",
                ref="p5",
                agent_id="a1",
                chain_seq=2,
                producer_id="prod-a",
                authenticated=True,
            ),
        ],
        {},
        0,
        None,
    ),
    (
        "SEC-011",
        "negative-identity-change-across-different-agents",
        [
            ev(
                "identity",
                ref="p6",
                agent_id="a1",
                chain_seq=1,
                producer_id="prod-a",
                authenticated=True,
            ),
            ev(
                "identity",
                ref="p7",
                agent_id="a2",
                chain_seq=2,
                producer_id="prod-b",
                authenticated=True,
            ),
        ],
        {},
        0,
        None,
    ),
]


def _findings_for(rule_id: str, events, cfg_kwargs: dict):
    cfg = RulesConfig(**cfg_kwargs)
    rules = [r for r in ALL_RULES if r.id == rule_id]
    assert len(rules) == 1, f"rule {rule_id} missing from ALL_RULES"
    return run_rules(events, cfg, rules)


@pytest.mark.parametrize("rule_id,name,events,cfg_kwargs,expected_n,subject", CASES)
def test_rule_case(rule_id, name, events, cfg_kwargs, expected_n, subject):
    findings = _findings_for(rule_id, events, cfg_kwargs)
    ids = ", ".join(f.explanation for f in findings)
    assert len(findings) == expected_n, f"{rule_id}/{name}: {ids}"
    if findings:
        assert findings[0].rule_id == rule_id
        assert findings[0].suppression_reason is None
        if subject is not None:
            assert findings[0].subject == subject


# --------------------------------------------------- suppression retention --


@pytest.mark.parametrize(
    "rule_id,events,cfg_kwargs,subject_key",
    [
        # documented ingest-batch delay for a specific agent/tool
        (
            "SEC-001",
            [
                _corr_event(
                    "receipt_missing", "t1", tool="http_fetch", agent_id="agent-batch", ref="rm1"
                )
            ],
            {},
            None,
        ),
        # documented load-generator for a specific subject
        (
            "SEC-005",
            [
                ev(
                    "tool_audit",
                    ref=f"c{i}",
                    mins=i / 2,
                    agent_id="agent-loadgen",
                    tool="shell",
                    outcome="success",
                )
                for i in range(21)
            ],
            {},
            "agent-loadgen/shell",
        ),
    ],
)
def test_suppressed_positive_is_retained_with_reason(rule_id, events, cfg_kwargs, subject_key):
    cfg = RulesConfig(
        **cfg_kwargs,
        suppressions=(
            Suppression(
                rule_id=rule_id,
                reason="documented suppression in versioned config; retained",
                agent_id="agent-batch" if rule_id == "SEC-001" else None,
                subject=subject_key,
            ),
        ),
    )
    rules = [r for r in ALL_RULES if r.id == rule_id]
    unsuppressed = run_rules(events, RulesConfig(**cfg_kwargs), rules)
    suppressed = run_rules(events, cfg, rules)
    # suppression retains the finding, never drops it (documented + visible)
    assert len(unsuppressed) == len(suppressed) == 1
    assert suppressed[0].suppression_reason is not None
    assert unsuppressed[0].suppression_reason is None
    # suppression is specific: unrelated finding keeps unsuppressed
    other = run_rules(events, RulesConfig(), rules)
    assert other[0].rule_id == rule_id


def test_suppression_scope_is_narrow():
    """A suppression naming tool=http_fetch must not cover tool=shell."""
    events = [_corr_event("receipt_missing", "t1", tool="shell")]
    cfg = RulesConfig(
        suppressions=(
            Suppression(
                rule_id="SEC-001",
                reason="covers http_fetch only, not shell",
                tool="http_fetch",
            ),
        )
    )
    rules = [r for r in ALL_RULES if r.id == "SEC-001"]
    findings = run_rules(events, cfg, rules)
    assert len(findings) == 1
    assert findings[0].suppression_reason is None


# ------------------------------------------------------------ PRIV-01 test --


def _all_fixture_events() -> list[Event]:
    events: list[Event] = []
    for _, _, case_events, _, _, _ in CASES:
        events.extend(case_events)
    # add a definite SEC-008 hit carrying the matched payload
    events.append(ev("ingest", ref="payload-probe", agent_id="a1", content=f"tok={SECRET}"))
    return events


def test_no_finding_ever_carries_raw_matched_content():
    """PRIV-01 / SEC-008: presence, not payload — the matched credential substring
    must never appear in ANY field of ANY finding, over every fixture."""
    findings = run_rules(_all_fixture_events(), RulesConfig())
    secrets_hits = [f for f in findings if f.rule_id == "SEC-008"]
    assert secrets_hits, "fixture must include a SEC-008 positive"
    for finding in findings:
        blob = (
            finding.explanation,
            finding.subject or "",
            finding.suppression_reason or "",
            " ".join(finding.evidence_refs),
            finding.rule_id,
            finding.rule_version,
            finding.severity,
            finding.confidence,
        )
        assert SECRET not in blob, (
            f"finding {finding.rule_id} leaked raw matched content field-wise"
        )


# ----------------------------------------------------------- framework tests


def test_all_eleven_rules_registered():
    assert [r.id for r in ALL_RULES] == [f"SEC-{i:03d}" for i in range(1, 12)]
    for r in ALL_RULES:
        assert r.version
        assert r.description


def test_run_rules_deterministic_and_sorted():
    events = _all_fixture_events()
    first = run_rules(events, RulesConfig())
    second = run_rules(list(reversed(events)), RulesConfig())
    assert first == second
    for f in first:
        assert f.severity in SEVERITIES
        assert f.confidence in CONFIDENCES
        assert f.rule_version


def test_correlation_state_distinction_in_fixtures():
    """Bypass corroboration only ever accepts receipt-existence states."""
    assert (
        frozenset({"matched", "duplicate", "ambiguous", "late_arrival"})
        == CORRELATED_RECEIPT_STATES
    )
    # receipt_missing / trace_missing / pending never corroborate
    assert "receipt_missing" not in CORRELATED_RECEIPT_STATES
    assert "trace_missing" not in CORRELATED_RECEIPT_STATES


def test_event_kinds_in_fixtures_are_valid():
    for _, _, case_events, _, _, _ in CASES:
        for e in case_events:
            assert e.kind in EVENT_KINDS


def test_event_rejects_unknown_kind():
    with pytest.raises(ValueError, match="unknown event kind"):
        ev("trace_telemetry_raw")


# ------------------------------------------------------------ config loading


def test_shipped_rules_yaml_loads_as_schema_v1():
    cfg = load_config(REPO_ROOT / "services" / "rules" / "config" / "rules.yaml")
    assert cfg.version == "1"
    assert "shell" in cfg.privileged_tools
    assert cfg.privileged_grace_seconds == 30.0
    assert cfg.verification_failure_states == frozenset({"invalid", "unsupported_schema"})
    assert cfg.deny_rate_threshold == 0.5
    assert cfg.tool_cycle_max_calls == 20
    assert "release-2026.11" in cfg.tool_baseline
    assert set(cfg.patterns) >= {"aws_access_key", "private_key_block"}
    assert cfg.custody_covered_tools == frozenset({"shell"})
    assert len(cfg.suppressions) == 2
    for s in cfg.suppressions:
        assert s.reason  # every suppression documents its reason


def test_shipped_config_suppressions_apply_to_engine():
    cfg = load_config(REPO_ROOT / "services" / "rules" / "config" / "rules.yaml")
    suppress_ids = {s.rule_id for s in cfg.suppressions}
    assert suppress_ids <= {r.id for r in ALL_RULES}


def test_shipped_yaml_matches_json_schema():
    """Lightweight schema conformance: required keys, const version, enum bounds."""
    import json  # noqa: PLC0415

    import yaml  # noqa: PLC0415

    schema = json.loads(
        (REPO_ROOT / "schemas" / "rules-config.schema.json").read_text(encoding="utf-8")
    )
    doc = yaml.safe_load(
        (REPO_ROOT / "services" / "rules" / "config" / "rules.yaml").read_text(encoding="utf-8")
    )
    assert schema["properties"]["version"]["const"] == doc["version"] == 1
    rules_section = schema["properties"]["rules"]["properties"]
    for key in doc["rules"]:
        assert key in rules_section, f"rules.{key} not in schema"
    for s in doc["rules"].get("suppressions", []):
        item_schema = rules_section["suppressions"]["items"]
        assert set(s) <= set(item_schema["properties"])
        assert s["rule_id"]
        assert len(s["reason"]) >= 8


def test_load_config_rejects_unknown_version(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 99\nrules: {}\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported rules-config version"):
        load_config(bad)


def test_shipped_config_fires_end_to_end():
    """The shipped v1 YAML, driven end-to-end, still produces findings."""
    cfg = load_config(REPO_ROOT / "services" / "rules" / "config" / "rules.yaml")
    events = [
        _corr_event("receipt_missing", "t1", tool="shell"),
        ev("tool_audit", ref="b1", tool="shell", privileged=True, trace_id="t2", outcome="success"),
        _corr_event("matched", "tX", decision="deny"),
        ev("tool_audit", ref="b2", outcome="success", trace_id="tX", tool="shell"),
        ev("custody", ref="c1", action="use", credential_id="cred-9", tool="shell", agent_id="a1"),
        ev("ingest", ref="s1", agent_id="a1", content=f"bearer {SECRET} ok"),
    ]
    findings = run_rules(events, cfg)
    by_rule = {f.rule_id for f in findings}
    assert {"SEC-001", "SEC-009", "SEC-004", "SEC-010", "SEC-008"} <= by_rule
    # shipped suppressions apply cleanly: none of these fixtures match them
    assert all(f.suppression_reason is None for f in findings)
    # and even end-to-end, no finding carries the matched payload
    for finding in findings:
        assert SECRET not in finding.explanation
        assert SECRET not in " ".join(finding.evidence_refs)
