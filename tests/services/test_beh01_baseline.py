# SPDX-License-Identifier: Apache-2.0
"""BEH-01 behavioural baseline engine tests.

Synthetic labelled windows with KNOWN shifts: each drift rule must fire on
its designed shift and stay silent on benign windows shaped like the
baseline. Baseline building and persistence must be byte-deterministic.
The corpus-level false-positive measure lives in tests/eval (labelled
data); this module proves the engine mechanics.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[2] / "services" / "rules" / "src"))

from oaa_rules import (
    ALL_RULES,
    BEH_RULES,
    Baseline,
    Event,
    LabelledRun,
    baseline_to_json,
    build_baseline,
    load_baseline,
    load_config,
    measure_false_positives,
    run_beh_rules,
    save_baseline,
)

T0 = dt.datetime(2026, 11, 4, 10, 0, 0, tzinfo=dt.UTC)
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
CONFIG = load_config(REPO_ROOT / "services" / "rules" / "config" / "rules.yaml")


def ev(
    i: int,
    mins: float = 0,
    agent: str = "a1",
    tool: str = "http_fetch",
    decision: str = "allow",
    outcome: str = "success",
    release: str | None = None,
    day: int = 0,
    **kw,
) -> Event:
    return Event(
        kind="tool_audit",
        at=T0 + dt.timedelta(days=day, minutes=mins),
        ref=f"r{agent}-{i}",
        agent_id=agent,
        tool=tool,
        decision=decision,
        outcome=outcome,
        release_id=release,
        synthetic=True,
        **kw,
    )


def window_run(rid: str, events, label: str = "benign", day: int = 1) -> LabelledRun:
    return LabelledRun(
        run_id=rid,
        label=label,
        events=tuple(events),
        window_start=T0 + dt.timedelta(days=day),
        window_end=T0 + dt.timedelta(days=day, hours=1),
    )


def benign_baseline() -> Baseline:
    """Four consistent benign runs: 1 step/run at 10:xx UTC, mostly allows."""
    runs = [window_run(f"b{i}", [ev(i)]) for i in range(4)]
    return build_baseline(runs, label="benign")


def test_baseline_distributions_shape() -> None:
    bl = benign_baseline()
    assert len(bl.tools) == 1
    t = bl.tools[0]
    assert (t.agent_id, t.tool) == ("a1", "http_fetch")
    assert t.runs_seen == 4 and t.call_counts == (1.0, 1.0, 1.0, 1.0)
    assert t.denial_ratio == 0.0 and t.hour_span == (10, 10)
    assert t.latency_p95_ms is None  # documented placeholder


def test_beh_a_fires_on_known_volume_shift() -> None:
    bl = benign_baseline()
    shifted = window_run("shift", [ev(i, mins=float(i)) for i in range(12)])
    findings = [f for f in run_beh_rules(bl, [shifted]) if f.rule_id == "BEH-A"]
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "medium" and f.confidence == "advisory"
    assert "not intent" in f.explanation


def test_beh_a_silent_on_benign_window() -> None:
    bl = benign_baseline()
    calm = window_run("calm", [ev(9)])
    assert not [f for f in run_beh_rules(bl, [calm]) if f.rule_id == "BEH-A"]


def test_beh_b_fires_on_denial_ratio_shift() -> None:
    bl = benign_baseline()
    denies = [
        ev(100 + i, day=1, mins=float(i), decision="deny", outcome="failure") for i in range(4)
    ]
    shifted = window_run("deny", denies)
    findings = [f for f in run_beh_rules(bl, [shifted]) if f.rule_id == "BEH-B"]
    assert len(findings) == 1
    assert findings[0].severity == "medium"  # zero-denial baseline => medium
    # a window under the min-call bound stays silent
    tiny = window_run("tiny", denies[:2])
    assert not [f for f in run_beh_rules(bl, [tiny]) if f.rule_id == "BEH-B"]


def test_beh_c_fires_on_late_hour_volume() -> None:
    bl = benign_baseline()
    late = [
        Event(
            kind="tool_audit",
            at=T0.replace(hour=23) + dt.timedelta(days=1),
            ref=f"n{i}",
            agent_id="a1",
            tool="http_fetch",
            decision="allow",
            outcome="success",
            synthetic=True,
        )
        for i in range(3)
    ]
    shifted = window_run("late", late, day=1)
    findings = [f for f in run_beh_rules(bl, [shifted]) if f.rule_id == "BEH-C"]
    assert len(findings) == 1 and findings[0].confidence == "advisory"


def test_beh_d_reuses_sec006_and_stays_advisory() -> None:
    bl = benign_baseline()
    # shell IS acknowledged for release-2026.11 in the shipped config
    off = [
        Event(
            kind="tool_audit",
            at=T0 + dt.timedelta(days=1),
            ref="off1",
            agent_id="a1",
            tool="http_fetch",
            decision="allow",
            outcome="success",
            privileged=True,
            release_id="release-2026.11",
            synthetic=True,
        )
    ]
    shifted = window_run("off", off)
    findings = [f for f in run_beh_rules(bl, [shifted], CONFIG) if f.rule_id == "BEH-D"]
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "low" and f.confidence == "advisory"
    assert "SEC-006 reused" in f.explanation
    # acknowledged tool stays silent
    ack = [
        Event(
            kind="tool_audit",
            at=T0 + dt.timedelta(days=1),
            ref="ack1",
            agent_id="a1",
            tool="shell",
            decision="allow",
            outcome="success",
            privileged=True,
            release_id="release-2026.11",
            synthetic=True,
        )
    ]
    assert not [
        f for f in run_beh_rules(bl, [window_run("ack", ack)], CONFIG) if f.rule_id == "BEH-D"
    ]


def test_beh_findings_never_state_intent() -> None:
    bl = benign_baseline()
    shifted = window_run("shift", [ev(i, mins=float(i)) for i in range(12)])
    for f in run_beh_rules(bl, [shifted]):
        assert "intent" not in f.explanation.replace("not intent", "")
        assert f.confidence == "advisory"
        assert f.severity in ("low", "medium")


def test_benign_window_over_full_baseline_is_fp_free() -> None:
    bl = benign_baseline()
    calm = window_run("calm", [ev(9)])
    m = measure_false_positives(bl, [window_run(f"b{i}", [ev(i)]) for i in range(4)] + [calm])
    assert m["fp_count"] == 0
    assert m["fp_bound"] == 1  # ceil(0.15 * 4 benign runs), documented bound


# ------------------------------------------------------ determinism + files


def test_baseline_building_is_deterministic(tmp_path: pathlib.Path) -> None:
    bl1 = benign_baseline()
    bl2 = benign_baseline()
    assert bl1.digest == bl2.digest

    assert baseline_to_json(bl1) == baseline_to_json(bl2)


def test_save_load_roundtrip_deterministic(tmp_path: pathlib.Path) -> None:
    bl = benign_baseline()
    p1 = save_baseline(tmp_path / "baselines", bl)
    p2 = save_baseline(tmp_path / "baselines", bl)
    assert p1 == p2  # content-addressed filename: no duplicate files
    loaded = load_baseline(p1)
    assert loaded.digest == bl.digest
    assert loaded.tools[0].as_dict() == bl.tools[0].as_dict()
    p3 = save_baseline(tmp_path / "baselines", loaded)
    assert p3 == p1
    reg = json.loads((tmp_path / "baselines" / "registry.json").read_text())
    assert [e["file"] for e in reg] == [p1.name]


def test_measurement_is_deterministic() -> None:
    bl = benign_baseline()
    runs = [window_run(f"b{i}", [ev(i)]) for i in range(4)]
    runs.append(window_run("shift", [ev(i, mins=float(i)) for i in range(12)], label="vol-shift"))
    m1 = measure_false_positives(bl, runs)
    m2 = measure_false_positives(bl, runs)
    assert m1 == m2 and m1["tp_count"] == 1


def test_beh_rules_do_not_join_all_rules() -> None:
    """BEH rules are advisory and take a baseline object; the SEC pipeline
    (run_rules over events) must be unchanged by BEH-01."""
    assert all(getattr(r, "id", "").startswith("SEC-") for r in ALL_RULES)


def test_no_baseline_key_stays_silent() -> None:
    """A window for an agent that has no baseline entry stays silent —
    absence of a baseline is an onboarding gap, not a finding (SEC-006
    semantics carried over to BEH-A/B/C)."""
    bl = benign_baseline()
    other = window_run("other", [ev(9, agent="unknown-agent"), ev(10, agent="unknown-agent")])
    assert run_beh_rules(bl, [other]) == []


def test_run_beh_rules_sorted_and_advisory() -> None:
    bl = benign_baseline()
    shifted = window_run("shift", [ev(i, mins=float(i)) for i in range(12)])
    fs = run_beh_rules(bl, [shifted])
    assert [f.rule_id for f in fs] == sorted(f.rule_id for f in fs)
    for f in fs:
        assert f.rule_id.startswith("BEH-")


@pytest.mark.parametrize("rule_id", ["BEH-A", "BEH-B", "BEH-C", "BEH-D"])
def test_beh_rule_metadata(rule_id: str) -> None:
    rule = next(r for r in BEH_RULES if r.id == rule_id)
    assert rule.version == "1.0.0" and rule.description
