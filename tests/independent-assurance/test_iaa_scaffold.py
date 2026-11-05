# SPDX-License-Identifier: Apache-2.0

"""OV-13 tests: the independent assurance agent is isolated and fail-visible."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

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
