# SPDX-License-Identifier: Apache-2.0
"""OV-10 mutation catalog v0 tests: synthetic campaigns, known outcomes."""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "mutation_catalog"
EXPECTATIONS = FIXTURES / "expectations.json"
RUNSET = FIXTURES / "runset.json"


def _load_compiler():
    spec = importlib.util.spec_from_file_location(
        "mutation_catalog", REPO / "tools" / "mutation_catalog" / "catalog.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_c = _load_compiler()
_DOC = json.loads(EXPECTATIONS.read_text())
_RUNSET = json.loads(RUNSET.read_text())


def _clean_catalog():
    return _c.run_campaign(_DOC, _RUNSET)


def test_every_mutation_is_killed_in_the_campaign():
    catalog = _clean_catalog()
    assert all(entry["killed"] for entry in catalog["mutations"])


def test_correct_detector_kills_each_mutation():
    catalog = _clean_catalog()
    assert {entry["mutation"]: sorted(entry["findings"]) for entry in catalog["mutations"]} == {
        "evidence-link-removal": ["evidence-integrity"],
        "boundary-widening": ["boundary-scope"],
        "review-route-bypass": ["review-route-presence"],
        "replay-duplicate": ["replay-duplicate"],
    }


def test_detector_summary_counts_are_explicit():
    catalog = _clean_catalog()
    for row in catalog["detector_summary"]:
        assert row["attempts"] == 1
        assert row["killed"] == 1
        assert row["survived"] == 0
        assert row["kill_ratio"] == 1.0
        # bounded claim: attempts == killed + survived
        assert row["killed"] + row["survived"] == row["attempts"]


def test_unmutated_runset_triggers_no_detector():
    # bounded claim on the other side: a clean campaign yields no findings.
    assert all(not detector(_DOC, _RUNSET) for detector in _c.DETECTORS.values())


def test_mutation_refuses_case_without_receipt_records():
    empty = {"schema_version": "agent_run_record/v1", "records": [], "case_bindings": {}}
    with pytest.raises(ValueError):
        _c.mutate(_DOC, empty, "replay-duplicate")
    with pytest.raises(ValueError):
        _c.mutate(_DOC, empty, "evidence-link-removal")


def test_unknown_mutation_is_refused():
    with pytest.raises(ValueError):
        _c.mutate(_DOC, _RUNSET, "not-a-mutation")


def test_surviving_mutation_is_counted_not_hidden():
    doc = json.loads(EXPECTATIONS.read_text())
    # strip the human_review declaration first (no privileged budget left:
    # bypassing an absent route must be unkillable by that detector).
    doc["cases"][0]["budgets"]["max_privileged_tool_calls"] = 0
    runset = json.loads(RUNSET.read_text())
    catalog = _c.run_campaign(doc, runset)
    entry = next(e for e in catalog["mutations"] if e["mutation"] == "review-route-bypass")
    assert entry["killed"] is False
    assert "uncaught" in entry
    row = next(r for r in catalog["detector_summary"] if r["detector"] == "review-route-presence")
    assert row["survived"] == 1
    assert row["kill_ratio"] == 0.0
    assert row["killed"] + row["survived"] == row["attempts"]


def test_main_exit_zero_writes_catalog(tmp_path):
    out = tmp_path / "catalog.json"
    assert (
        _c.main(
            ["--expectations", str(EXPECTATIONS), "--runset", str(RUNSET), "--output", str(out)]
        )
        == 0
    )
    catalog = json.loads(out.read_text())
    assert catalog["schema_version"] == "mutation_catalog/v0"
    assert len(catalog["mutations"]) == 4


def test_human_summary_includes_bounded_ratios():
    catalog = _clean_catalog()
    for line in catalog["human_summary"].splitlines():
        if "killed (survived" in line:
            assert "bounded to recorded attempts" in line
            break
    else:
        raise AssertionError(catalog["human_summary"])
