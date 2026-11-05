# SPDX-License-Identifier: Apache-2.0

"""OV-13 tests: the independent assurance agent is isolated and fail-visible."""

from __future__ import annotations

import ast
import importlib.util
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[2] / "services" / "independent-assurance" / "src"


def _env() -> dict[str, str]:
    return {"PYTHONPATH": str(SRC), "PATH": "/usr/bin:/bin"}


def _run(evidence: str):
    return subprocess.run(
        [sys.executable, "-m", "oaa_iaa"],
        input=evidence,
        capture_output=True,
        text=True,
        env=_env(),
        timeout=30,
    )


def _module_source() -> str:
    return (SRC / "oaa_iaa" / "__main__.py").read_text(encoding="utf-8")


def test_module_imports_stdlib_only() -> None:
    tree = ast.parse(_module_source())
    modules = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            modules.add(node.module.split(".")[0])
    assert modules <= {"json", "sys", "__future__"}, modules


def test_review_opinion_on_prebind_indicators() -> None:
    evidence = json.dumps(
        {
            "schema": "oaa.prebind-indicators/v1",
            "counts": {
                "admitted": 5,
                "held": 0,
                "narrowed": 0,
                "escalated": 0,
                "refused": 2,
                "quarantined": 0,
                "no_bind": 0,
                "unresolved": 3,
            },
        }
    )
    proc = _run(evidence)
    assert proc.returncode == 0, proc.stderr
    opinion = json.loads(proc.stdout)
    assert opinion["schema"] == "oaa.independent-review-opinion/v1"
    assert opinion["verdict"] == "concern"
    codes = {c["code"] for c in opinion["concerns"]}
    assert "UNRESOLVED_BOUNDARY_OUTCOMES" in codes
    assert "STATE_NOT_EVIDENCED" in codes
    assert "NO_SCHEMA_DECLARED" not in codes


def test_missing_schema_is_fail_visible() -> None:
    proc = _run(json.dumps({"anything": True}))
    assert proc.returncode == 0
    opinion = json.loads(proc.stdout)
    assert opinion["verdict"] == "fail"
    assert any(c["code"] == "NO_SCHEMA_DECLARED" for c in opinion["concerns"])


def test_malformed_input_exits_non_zero_with_stderr() -> None:
    proc = _run("not json")
    assert proc.returncode == 1
    assert "not valid JSON" in proc.stderr


def test_non_object_input_exits_non_zero() -> None:
    proc = _run("[1, 2]")
    assert proc.returncode == 1
    assert "JSON object" in proc.stderr


def test_unknown_argument_exits_non_zero() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "oaa_iaa", "bogus"],
        capture_output=True,
        text=True,
        env=_env(),
        timeout=30,
    )
    assert proc.returncode == 2
    assert "unknown argument" in proc.stderr


def test_opinion_cites_only_document_carried_assertions() -> None:
    evidence = json.dumps({"schema": "test/v1"})
    opinion = json.loads(_run(evidence).stdout)
    # schema declared, no indicators: the agent cites nothing affirmative
    # and finds nothing to concern - verdict pass on the handed content only
    assert opinion["positives"] == []
    assert opinion["concerns"] == []
    assert opinion["verdict"] == "pass"


def _iaa_review(evidence: str) -> dict:
    proc = _run(evidence)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_revalidation_report_reproduced_is_corroborated() -> None:
    report = json.dumps(
        {
            "schema": "oaa.revalidation-report/v1",
            "verdict": "REPRODUCED",
            "checks": [
                {"status": "PASS", "message": "packet digest re-derives from the packet body"},
                {"status": "PASS", "message": "packet body reproduces exactly"},
            ],
        }
    )
    opinion = _iaa_review(report)
    assert opinion["verdict"] == "pass"
    assert any(
        p["code"] == "REVALIDATION_REPRODUCED" and p["citation"] == "verdict == REPRODUCED"
        for p in opinion["positives"]
    )
    assert any(p["checks_cited"] == 2 for p in opinion["positives"])
    assert opinion["concerns"] == []


def test_revalidation_report_mismatch_is_fail_visible() -> None:
    report = json.dumps(
        {
            "schema": "oaa.revalidation-report/v1",
            "verdict": "MISMATCH",
            "checks": [{"status": "FAIL", "message": "re-derived packet differs at gate_coverage"}],
        }
    )
    opinion = _iaa_review(report)
    assert opinion["verdict"] == "fail"
    mismatch = [c for c in opinion["concerns"] if c["code"] == "REVALIDATION_MISMATCH"]
    assert mismatch, opinion
    assert mismatch[0]["citation"] == "verdict == MISMATCH"
    assert mismatch[0]["count"] == 1


def test_revalidation_report_unreadable_verdict_is_named() -> None:
    report = json.dumps({"schema": "oaa.revalidation-report/v1"})
    opinion = _iaa_review(report)
    assert opinion["verdict"] == "fail"
    assert any(c["code"] == "REVALIDATION_VERDICT_UNREADABLE" for c in opinion["concerns"])


def test_end_to_end_revalidate_report_piped_to_iaa(tmp_path: Path) -> None:
    """revalidate_packet --report -> its document -> oaa_iaa cites the verdict."""
    rv_spec = importlib.util.spec_from_file_location(
        "oaa_revalidate_packet",
        Path(__file__).resolve().parents[2] / "tools" / "verifier" / "revalidate_packet.py",
    )
    assert rv_spec is not None, rv_spec
    assert rv_spec.loader is not None
    rv = importlib.util.module_from_spec(rv_spec)
    rv_spec.loader.exec_module(rv)
    store = (
        Path(__file__).resolve().parents[2]
        / "services"
        / "investigation-ui"
        / "demo_data"
        / "evidence_store.jsonl"
    )
    packet = rv.rederive_packet_from_inputs(store)
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n")
    report_path = tmp_path / "report.json"
    assert (
        rv.main(
            [
                "--packet",
                str(packet_path),
                "--evidence-store",
                str(store),
                "--report",
                str(report_path),
            ]
        )
        == 0
    )
    opinion = _iaa_review(report_path.read_text())
    # the packet re-derives from its own store, so the honest verdict is
    # REPRODUCED and the agent corroborates it with a citation
    assert opinion["verdict"] == "pass"
    assert any(p["code"] == "REVALIDATION_REPRODUCED" for p in opinion["positives"])


# --------------------------------------------------- OV-20 in-process unit --
# The subprocess runs above are the isolation contract but are not traced by
# pytest-cov; these in-process tests exercise the same review/main branches so
# the OV-20 code paths carry measurable coverage too.


@pytest.fixture
def oaa_iaa():
    spec = importlib.util.spec_from_file_location(
        "oaa_iaa_isolated", SRC / "oaa_iaa" / "__main__.py"
    )
    assert spec is not None, spec
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _review_revalidation(oaa_iaa, verdict, checks):
    return oaa_iaa._review_revalidation_report(
        {"schema": "oaa.revalidation-report/v1", "verdict": verdict, "checks": checks}
    )


def test_revalidation_mismatch_in_process(oaa_iaa) -> None:
    opinion = _review_revalidation(
        oaa_iaa,
        "MISMATCH",
        [{"status": "FAIL", "message": "re-derived packet differs at gate_coverage"}],
    )
    assert opinion["verdict"] == "fail"
    assert opinion["concerns"][0]["count"] == 1


def test_revalidation_reproduced_with_failing_check_is_concern(oaa_iaa) -> None:
    opinion = _review_revalidation(
        oaa_iaa,
        "REPRODUCED",
        [{"status": "FAIL", "message": "re-derived packet differs at gate_coverage"}],
    )
    assert opinion["verdict"] == "fail"
    assert any(c["code"] == "FAILING_CHECK_UNDER_REPRODUCED_VERDICT" for c in opinion["concerns"])


def test_revalidation_reproduced_green_cites_pass_count(oaa_iaa) -> None:
    opinion = _review_revalidation(
        oaa_iaa,
        "REPRODUCED",
        [{"status": "PASS", "message": "packet digest re-derives"}],
    )
    assert opinion["verdict"] == "pass"
    assert opinion["positives"][0]["checks_cited"] == 1
    assert opinion["concerns"] == []
    assert "isolate process" in opinion["isolation_note"]


def test_revalidation_unrecognised_verdict_is_fail_visible(oaa_iaa) -> None:
    opinion = _review_revalidation(oaa_iaa, "GREEN", [])
    assert opinion["verdict"] == "fail"
    assert any(c["code"] == "REVALIDATION_VERDICT_UNRECOGNISED" for c in opinion["concerns"])


def test_malformed_checks_list_does_not_crash(oaa_iaa) -> None:
    opinion = _review_revalidation(oaa_iaa, "REPRODUCED", "not-a-list")
    assert opinion["verdict"] == "pass"
    assert opinion["positives"][0]["checks_cited"] == 0


def test_non_report_document_is_not_a_revalidation_review(oaa_iaa) -> None:
    other = oaa_iaa._review_revalidation_report(
        {"schema": "oaa.prebind-indicators/v1", "verdict": "REPRODUCED", "checks": []}
    )
    assert other is None


def test_main_unknown_argument_exits_two(oaa_iaa, capsys) -> None:
    assert oaa_iaa.main(["lint"]) == 2
    assert "unknown argument" in capsys.readouterr().err


def test_main_invalid_json_exits_one(oaa_iaa, monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("{not json"))
    assert oaa_iaa.main([]) == 1
    assert "not valid JSON" in capsys.readouterr().err


def test_main_non_object_exits_one(oaa_iaa, monkeypatch, capsys) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("[1, 2]"))
    assert oaa_iaa.main([]) == 1
    assert "must be a JSON object" in capsys.readouterr().err


def test_main_writes_revalidation_opinion(oaa_iaa, monkeypatch, capsys) -> None:
    report = json.dumps(
        {
            "schema": "oaa.revalidation-report/v1",
            "verdict": "REPRODUCED",
            "checks": [{"status": "PASS", "message": "packet body reproduces"}],
        }
    )
    monkeypatch.setattr("sys.stdin", io.StringIO(report))
    assert oaa_iaa.main(["review"]) == 0
    opinion = json.loads(capsys.readouterr().out)
    assert opinion["verdict"] == "pass"
    assert opinion["positives"][0]["code"] == "REVALIDATION_REPRODUCED"


def test_main_explicit_none_argv_reads_stdin(oaa_iaa, monkeypatch, capsys) -> None:
    monkeypatch.setattr(sys, "argv", ["oaa_iaa"])
    monkeypatch.setattr(
        "sys.stdin", io.StringIO(json.dumps({"schema": "oaa.revalidation-report/v1"}))
    )
    assert oaa_iaa.main(None) == 0
    opinion = json.loads(capsys.readouterr().out)
    assert opinion["verdict"] == "fail"
    assert opinion["concerns"][0]["code"] == "REVALIDATION_VERDICT_UNREADABLE"
