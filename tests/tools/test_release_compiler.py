# SPDX-License-Identifier: Apache-2.0
"""OV-9 release compiler tests: classification per declared control."""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
FIXTURES = REPO / "tests" / "fixtures" / "release_compiler"
EXPECTATIONS = FIXTURES / "expectations.yaml"
BASELINE = FIXTURES / "baseline.json"
CANDIDATE = FIXTURES / "candidate.json"


def _load_compiler():
    spec = importlib.util.spec_from_file_location(
        "release_compiler", REPO / "tools" / "release_compiler" / "compile.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_c = _load_compiler()


def _compile():
    expectations = _c.load_expectations(EXPECTATIONS)
    baseline = _c.validate_run_set(_c.load_json(BASELINE))
    candidate = _c.validate_run_set(_c.load_json(CANDIDATE))
    return _c.compile_comparison(expectations, baseline, candidate)


def test_main_exit_zero_and_writes_report(tmp_path):
    out = tmp_path / "comparison.json"
    assert (
        _c.main(
            [
                "--expectations",
                str(EXPECTATIONS),
                "--baseline",
                str(BASELINE),
                "--candidate",
                str(CANDIDATE),
                "--output",
                str(out),
            ]
        )
        == 0
    )
    report = json.loads(out.read_text())
    assert report["schema_version"] == "release_comparison/v1"


def test_every_classification_is_exercised_once():
    report = _compile()
    classes = {entry["case_id"]: entry["classification"] for entry in report["cases"]}
    assert classes == {
        "gate-allow-stable": "preserved_controls",
        "gate-deny-evidence": "new_failure",
        "boundary-tool-scope": "new_failure",
        "recovered-unknown": "improved",
        "persistent-deny-case": "persistent_failure",
    }
    assert report["summary"] == {
        "new_failure": 2,
        "persistent_failure": 1,
        "preserved_controls": 1,
        "improved": 1,
    }


def test_weakened_evidence_control_is_caught():
    # Deliberate weakening: the candidate dropped the required deny receipt.
    report = _compile()
    entry = next(e for e in report["cases"] if e["case_id"] == "gate-deny-evidence")
    assert entry["baseline"]["pass"] is True
    assert entry["candidate"]["pass"] is False
    assert any("required-evidence-missing" in r for r in entry["candidate"]["reasons"])


def test_weakened_tool_boundary_is_caught():
    # Deliberate weakening: candidate used a tool outside the case boundaries.
    report = _compile()
    entry = next(e for e in report["cases"] if e["case_id"] == "boundary-tool-scope")
    assert entry["baseline"]["pass"] is True
    assert entry["classification"] == "new_failure"
    assert any("'shell'" in r for r in entry["candidate"]["reasons"])


def test_unknown_never_maps_into_pass():
    expectations = _c.load_expectations(EXPECTATIONS)
    baseline = _c.validate_run_set(_c.load_json(BASELINE))
    case = next(c for c in expectations["cases"] if c["case_id"] == "recovered-unknown")
    result = _c.evaluate_case(case, baseline)
    assert result["pass"] is False
    assert any("unknown" in r for r in result["reasons"])


def test_persistent_failure_reports_both_sides_failing():
    report = _compile()
    entry = next(e for e in report["cases"] if e["case_id"] == "persistent-deny-case")
    assert entry["baseline"]["pass"] is False
    assert entry["candidate"]["pass"] is False


def test_unbound_case_fails_closed():
    expectations = _c.load_expectations(EXPECTATIONS)
    empty = {"schema_version": "agent_run_record/v1", "records": [], "case_bindings": {}}
    case = expectations["cases"][0]
    result = _c.evaluate_case(case, empty)
    assert result["pass"] is False
    assert any("no-records-bound" in r for r in result["reasons"])


def test_improved_classification_from_fail_to_pass():
    report = _compile()
    entry = next(e for e in report["cases"] if e["case_id"] == "recovered-unknown")
    assert entry["baseline"]["pass"] is False
    assert entry["candidate"]["pass"] is True
    assert entry["classification"] == "improved"


def test_human_summary_names_all_classifications():
    report = _compile()
    summary = report["human_summary"]
    for token in (
        "preserved controls",
        "new failure",
        "improved",
        "persistent failure",
        "NOT SAFE TO SIGN OFF",
    ):
        assert token in summary, summary


def test_invalid_run_record_is_refused(tmp_path):
    bad = tmp_path / "bad.json"
    raw = _c.load_json(CANDIDATE)
    raw["records"][0].pop("record_id")  # schema-required field
    raw["case_bindings"] = {}
    bad.write_text(json.dumps(raw))
    with pytest.raises(ValueError):
        _c.validate_run_set(raw)
    assert (
        _c.main(
            [
                "--expectations",
                str(EXPECTATIONS),
                "--baseline",
                str(BASELINE),
                "--candidate",
                str(bad),
                "--output",
                str(tmp_path / "o.json"),
            ]
        )
        == 1
    )


def test_dangling_case_binding_is_refused():
    raw = _c.load_json(BASELINE)
    raw["case_bindings"] = {"gate-allow-stable": ["does-not-exist"]}
    with pytest.raises(ValueError):
        _c.validate_run_set(raw)


def test_determinism_same_inputs_byte_identical_output():
    first = _compile()
    second = _compile()
    assert json.dumps(first, indent=2, sort_keys=False) == json.dumps(
        second, indent=2, sort_keys=False
    )


def test_unwritable_output_path_is_clean_error(tmp_path, capsys):
    out = tmp_path / "no-such-dir" / "comparison.json"
    rc = _c.main(
        [
            "--expectations",
            str(EXPECTATIONS),
            "--baseline",
            str(BASELINE),
            "--candidate",
            str(CANDIDATE),
            "--output",
            str(out),
        ]
    )
    assert rc == 1
    captured = capsys.readouterr()
    assert captured.err.startswith("error: ")
    assert not out.exists()


def test_docstring_documents_conditional_tool_scope_checks():
    docstring = (_c.__doc__ or "").lower()
    assert "tool-scope checks run only where" in docstring
    assert "boundaries.tools" in docstring
