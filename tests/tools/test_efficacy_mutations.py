# SPDX-License-Identifier: Apache-2.0
"""OV-10 mutation catalog + efficacy campaign v0 tests.

Deterministic fixtures; every kill ratio asserted exactly.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, REPO / "tools" / "efficacy" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


mutations = _load("mutations")
efficacy = _load("efficacy")

EXPECTED_CLASSES = (
    "evidence_link_removal",
    "review_route_bypass",
    "boundary_widening",
    "replay_duplicate",
)
EXPECTED_DETECTORS = (
    "linkage_detector",
    "review_route_detector",
    "boundary_detector",
    "replay_detector",
)


# --- catalog / fixture invariants ------------------------------------


def test_catalog_has_exactly_the_four_v0_classes():
    assert tuple(mutations.catalog_ids()) == EXPECTED_CLASSES


def test_good_fixture_passes_every_detector():
    record = mutations.good_run_record()
    for detector_id, fn in efficacy.DETECTORS.items():
        findings = fn(record)
        assert findings == [], f"good fixture flagged by {detector_id}: {findings}"


def test_mutate_never_edits_the_base_fixture():
    record = mutations.good_run_record()
    snapshot = copy.deepcopy(record)
    for mid in mutations.catalog_ids():
        _ = mutations.MUTATIONS[mid].apply(record)
    assert record == snapshot, "a mutator edited its input"


def test_mutations_are_deterministic():
    base = mutations.good_run_record()
    for mid in mutations.catalog_ids():
        first = mutations.MUTATIONS[mid].apply(base)
        second = mutations.MUTATIONS[mid].apply(base)
        assert first == second, mid


# --- per-class kills --------------------------------------------------


def test_evidence_link_removal_killed_by_linkage_detector():
    record = mutations.MUTATIONS["evidence_link_removal"].apply(mutations.good_run_record())
    findings = efficacy.linkage_detector(record)
    assert findings, "expected evidence-link removal to be caught"
    # The untouched sibling control stays quiet so the kill is attributable.
    clean = [r for r in record["capability_refs"] if "via_receipt_hash" in r]
    assert len(clean) == 0


def test_review_route_bypass_killed_by_review_route_detector():
    record = mutations.MUTATIONS["review_route_bypass"].apply(mutations.good_run_record())
    findings = efficacy.review_route_detector(record)
    assert findings, "expected forged review approval to be caught"
    assert any("no approved_by" in f for f in findings)


def test_boundary_widening_killed_by_boundary_detector():
    record = mutations.MUTATIONS["boundary_widening"].apply(mutations.good_run_record())
    findings = efficacy.boundary_detector(record)
    assert findings, "expected boundary widening to be caught"
    assert any("boundary widening" in f for f in findings)


def test_replay_duplicate_killed_by_replay_detector():
    record = mutations.MUTATIONS["replay_duplicate"].apply(mutations.good_run_record())
    findings = efficacy.replay_detector(record)
    assert findings, "expected replay duplicate to be caught"
    assert any("duplicate in receipt list" in f for f in findings)
    assert any("replays receipt" in f for f in findings)


def test_unknown_governance_event_with_unresolveable_hash_is_flagged():
    record = mutations.good_run_record()
    record["governance_events"].append(
        {"kind": "receipt-attached", "decision": "allow", "receipt_hash": "sha256:" + "ff" * 32}
    )
    assert efficacy.linkage_detector(record), "unresolveable receipt link must be flagged"


# --- campaign summary: bounded claims, exact ratios -------------------


def _summary():
    return efficacy.run_campaign()


def test_campaign_runs_bounded_population():
    summary = _summary()
    assert summary["total_classes_run"] == 4
    assert summary["campaign_id"] == "ov10-efficacy-v0"


def test_campaign_kills_every_class_and_exact_ratios():
    summary = _summary()
    assert summary["total_survived"] == 0
    assert summary["survivors"] == []
    assert summary["all_controls_hold"] is True
    assert summary["total_killed"] == 4
    for detector_id in EXPECTED_DETECTORS:
        entry = summary["per_detector"][detector_id]
        assert entry["assignable_count"] == 1
        assert entry["caught"] == 1
        assert entry["kill_ratio"] == 1.0
    for class_id in EXPECTED_CLASSES:
        assert summary["per_class"][class_id]["killed"] is True
        assert summary["per_class"][class_id]["class_mutations_run"] == 1


def test_campaign_summary_carries_bounded_claims_scope():
    summary = _summary()
    assert "ONLY the v0 catalog classes" in summary["claims_scope"]
    assert summary["mutation_catalog_version"] == mutations.MUTATION_CATALOG_VERSION


def test_detector_assignment_is_total_over_the_catalog():
    assigned = set()
    for classes in efficacy.DETECTOR_ASSIGNMENT.values():
        assigned |= classes
    assert assigned == set(EXPECTED_CLASSES)


# --- CLI --------------------------------------------------------------


def test_cli_exits_zero_and_prints_summary_json():
    script = REPO / "tools" / "efficacy" / "efficacy.py"
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO),
        env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    summary = json.loads(proc.stdout)
    assert summary["all_controls_hold"] is True
    assert "verdicts" not in summary  # default run omits per-mutation verdicts

    full = subprocess.run(
        [sys.executable, str(script), "--full"],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=str(REPO),
        env={"PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    assert full.returncode == 0
    assert "verdicts" in json.loads(full.stdout)
