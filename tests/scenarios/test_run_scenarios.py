# SPDX-License-Identifier: Apache-2.0
"""OV-26 scenario-bank harness tests.

Suite validation (taxonomy ids resolve, structure), determinism of the
scenario-results document, and honesty checks (banking/insurance scenarios
are UNEXECUTED; no fixture-less scenario is ever classified EXECUTED_*).
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[2]
SUITES = REPO / "tools" / "scenarios" / "suites"
RUN = REPO / "tools" / "scenarios" / "run.py"


def _load(name, path=None):
    spec = importlib.util.spec_from_file_location(name, path or RUN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


run_mod = _load("scenarios_run")

TAXONOMY_IDS = {
    row["id"]
    for row in json.loads((REPO / "schemas" / "scenario-taxonomy" / "taxonomy.json").read_text())[
        "rows"
    ]
}


def _suite(context: str) -> dict:
    return run_mod.load_suite(SUITES / f"{context}.yaml")


def _cli_json(paths) -> str:
    """Run the harness the same way the tests drive it and return stdout JSON."""
    proc = subprocess.run(
        [str(_venv_python()), str(RUN), *[str(p) for p in paths]],
        capture_output=True,
        text=True,
        cwd=REPO,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def _venv_python() -> pathlib.Path:
    return pathlib.Path(sys.executable)


# --- suite validation -----------------------------------------------------


def test_every_scenario_risk_category_resolves_in_taxonomy() -> None:
    for path in sorted(SUITES.glob("*.yaml")):
        suite = run_mod.load_suite(path)
        for sc in suite["scenarios"]:
            assert sc["risk_category"] in TAXONOMY_IDS, f"{path.name}:{sc['id']}"


def test_every_scenario_carries_required_fields() -> None:
    for path in sorted(SUITES.glob("*.yaml")):
        suite = run_mod.load_suite(path)
        assert suite["context"] in ("banking", "insurance", "ops")
        for sc in suite["scenarios"]:
            for key in (
                "id",
                "risk_category",
                "description",
                "expected_gate_decisions",
                "on_unknown",
                "evidence_requirements",
            ):
                assert key in sc, f"{path.name}:{sc['id']}:{key}"
            assert sc["on_unknown"] in ("fail", "escalate")


def test_invalid_taxonomy_id_is_rejected() -> None:
    suite = _suite("ops")
    suite["scenarios"][0]["risk_category"] = "NOT-IN-TAXONOMY"
    try:
        run_mod.run_suite(suite, run_mod.load_run_records(), TAXONOMY_IDS)
    except run_mod.SuiteError as exc:
        assert "does not resolve" in str(exc)
    else:
        raise AssertionError("suite with unknown taxonomy id was accepted")


def test_duplicate_scenario_id_is_rejected() -> None:
    suite = _suite("ops")
    suite["scenarios"].append(dict(suite["scenarios"][0]))
    try:
        run_mod.validate_suite(suite, TAXONOMY_IDS)
    except run_mod.SuiteError as exc:
        assert "duplicate id" in str(exc)
    else:
        raise AssertionError("duplicate scenario id was accepted")


def test_malformed_receipt_hash_is_rejected() -> None:
    suite = _suite("ops")
    suite["scenarios"][0]["run_record_bindings"][0]["receipt_hashes"] = ["not-a-hash"]
    try:
        run_mod.validate_suite(suite, TAXONOMY_IDS)
    except run_mod.SuiteError as exc:
        assert "sha256:" in str(exc)
    else:
        raise AssertionError("non-sha256 receipt hash was accepted")


# --- execution semantics ---------------------------------------------------


def test_ops_scenarios_execute_from_committed_fixtures() -> None:
    results = run_mod.run_suite(_suite("ops"), run_mod.load_run_records(), TAXONOMY_IDS)
    assert results["scenarios_executed"] == 5
    assert all(r["outcome"] != "UNEXECUTED" for r in results["results"])
    assert results["outcome_counts"]["EXECUTED_PASS"] >= 3
    assert results["outcome_counts"]["EXECUTED_ESCALATED"] >= 1


def test_unknown_never_classifies_as_pass_without_escalation() -> None:
    sc = _suite("ops")["scenarios"][3]  # sce-ops-004 declares on_unknown: fail
    records = run_mod.load_run_records()
    outcome = run_mod.run_scenario(sc, records)
    assert sc["on_unknown"] == "fail"
    assert outcome["outcome"] == "EXECUTED_FAIL"
    assert "unknown" in outcome["observed_decisions"]


def test_no_fixture_scenario_is_unexecuted_and_never_pass() -> None:
    for context in ("banking", "insurance"):
        results = run_mod.run_suite(_suite(context), run_mod.load_run_records(), TAXONOMY_IDS)
        assert results["scenarios_executed"] > 0
        for r in results["results"]:
            assert r["outcome"] == "UNEXECUTED", (
                f"{context}/{r['scenario_id']} classified {r['outcome']} without fixtures"
            )
            assert "no committed run-record fixture" in str(
                r["detail"]["reason"]
            ) or "absent from the committed run records" in str(r["detail"]["reason"])


def test_missing_bound_record_is_reported_unexecuted() -> None:
    suite = _suite("ops")
    sc = suite["scenarios"][0]
    sc["run_record_bindings"] = [
        {
            "record_id": "arr-run-does-not-exist",
            "receipt_hashes": ["sha256:abc"],
            "expectation_case_id": "demo-gate-deny",
        }
    ]
    outcome = run_mod.run_scenario(sc, run_mod.load_run_records())
    assert outcome["outcome"] == "UNEXECUTED"
    assert "arr-run-does-not-exist" in outcome["reason"]


def test_binding_with_absent_hash_degrades_to_unexecuted() -> None:
    suite = _suite("ops")
    sc = suite["scenarios"][0]
    sc["run_record_bindings"][0]["receipt_hashes"].append("sha256:synth-absent-hash-cannot-exist")
    outcome = run_mod.run_scenario(sc, run_mod.load_run_records())
    assert outcome["outcome"] == "UNEXECUTED"


# --- determinism ------------------------------------------------------------


def test_results_document_is_byte_identical_across_runs() -> None:
    lines_a = _cli_json([SUITES / "ops.yaml", SUITES / "banking.yaml", SUITES / "insurance.yaml"])
    lines_b = _cli_json([SUITES / "ops.yaml", SUITES / "banking.yaml", SUITES / "insurance.yaml"])
    assert lines_a == lines_b and lines_a.strip()


def test_results_document_has_no_wallclock_content() -> None:
    doc = json.loads(_cli_json([SUITES / "ops.yaml"]))
    assert doc["schema_version"] == "scenario_results/v1"
    assert "timestamp" not in json.dumps(doc).lower()
    assert "generated_at" not in json.dumps(doc).lower()


def test_cli_fail_on_executed_fail_exits_one_on_fail_scenario() -> None:

    proc = subprocess.run(
        [str(_venv_python()), str(RUN), "--fail-on-executed-fail", str(SUITES / "ops.yaml")],
        capture_output=True,
        text=True,
        cwd=REPO,
        env={"PATH": "/usr/bin:/bin"},
    )
    # ops contains one deliberate unknown-resolves-to-fail scenario.
    assert proc.returncode == 1, proc.stdout
    doc = json.loads(proc.stdout)
    fails = [r for s in doc["suites"] for r in s["results"] if r["outcome"] == "EXECUTED_FAIL"]
    assert fails and fails[0]["scenario_id"] == "sce-ops-004-unknown-never-passes-silently"


def test_cli_rejects_invalid_suite_with_error_and_exit_one() -> None:
    (REPO / ".hermes-scratch-bad-suite.yaml").write_text(
        "suite_id: broken\ncontext: ops\nscenarios:\n  - id: x\n", encoding="utf-8"
    )
    try:
        proc = subprocess.run(
            [str(_venv_python()), str(RUN), str(REPO / ".hermes-scratch-bad-suite.yaml")],
            capture_output=True,
            text=True,
            cwd=REPO,
            env={"PATH": "/usr/bin:/bin"},
        )
    finally:
        (REPO / ".hermes-scratch-bad-suite.yaml").unlink(missing_ok=True)
    assert proc.returncode == 1
    assert proc.stderr.startswith("error:")


def test_cli_output_writes_deterministic_file() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "results.json"
        proc = subprocess.run(
            [str(_venv_python()), str(RUN), str(SUITES / "ops.yaml"), "--output", str(out)],
            capture_output=True,
            text=True,
            cwd=REPO,
            env={"PATH": "/usr/bin:/bin"},
        )
        assert proc.returncode == 0
        text = out.read_text(encoding="utf-8")
        assert json.loads(text)["suites"][0]["suite_id"] == "ops-investigation-bank"
        assert text == _cli_json([SUITES / "ops.yaml"])
