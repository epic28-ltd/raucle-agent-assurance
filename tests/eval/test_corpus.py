# SPDX-License-Identifier: Apache-2.0
"""EVAL-01 — pytest runner for the synthetic regression corpus.

- corpus content test: schema, EXACTLY 100 cases, exact plan class table,
  spec self-consistency;
- determinism test: the committed corpus bytes equal a fresh generation, and
  two fresh generations are byte-identical;
- 100 parametrized replay assertions: every case must match its DESIGNED
  expectation (correlation states + SEC finding set) under the shipped
  versioned rules config, offline (no tools, no secrets, no model calls).
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
CORPUS_PATH = HERE / "corpus" / "corpus.json"
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

for _p in ("services/correlation/src", "services/rules/src"):
    sys.path.insert(0, str(REPO_ROOT / _p))

from oaa_rules import load_config  # noqa: E402

_spec = importlib.util.spec_from_file_location("eval_generate_corpus", HERE / "generate_corpus.py")
_gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_gen)  # type: ignore[union-attr]
_spec2 = importlib.util.spec_from_file_location("eval_run_corpus", HERE / "run_corpus.py")
_run = importlib.util.module_from_spec(_spec2)
_spec2.loader.exec_module(_run)  # type: ignore[union-attr]

CORPUS = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
CASES = CORPUS["cases"]
CONFIG = load_config(REPO_ROOT / "services" / "rules" / "config" / "rules.yaml")

SCEN = frozenset(_gen.SCENARIO_CLASSES)
CORR_STATES = frozenset(_run.CORRELATION_STATES)


# ---------------------------------------------------------------- schema ----


def test_corpus_is_exactly_100_cases() -> None:
    assert len(CASES) == 100


def test_corpus_class_table_matches_plan() -> None:
    counts: dict[str, int] = {}
    for c in CASES:
        counts[c["scenario_class"]] = counts.get(c["scenario_class"], 0) + 1
    assert counts == _gen.CLASS_COUNTS


def test_corpus_version_stamped() -> None:
    assert CORPUS["corpus_version"] == _gen.CORPUS_VERSION
    assert CORPUS["seed"] == _gen.GENERATOR_SEED
    for c in CASES:
        assert c["metadata"]["generated_by"] == CORPUS["corpus_version"]
        assert c["metadata"]["synthetic"] is True


def test_corpus_schema() -> None:
    for c in CASES:
        assert set(c) >= {
            "case_id",
            "scenario_class",
            "description",
            "agent_id",
            "application",
            "steps",
            "extra_index_events",
            "expected",
            "metadata",
        }
        assert c["scenario_class"] in SCEN
        assert c["case_id"].startswith("EVAL-01-") or c["case_id"].split("-")[0].isupper()
        assert c["description"]
        gate_values: set[str | None] = set()
        for s in c["steps"]:
            assert {
                "tool",
                "trace_id",
                "gate",
                "outcome",
                "correlation",
                "emit_tool_audit",
                "privileged",
            } <= set(s)
            assert s["correlation"] in CORR_STATES
            assert s["gate"] in {"allow", "deny", None}
            assert isinstance(s["emit_tool_audit"], bool)
            gate_values.add(s["gate"])
        for e in c["extra_index_events"]:
            assert {"kind", "offset_minutes"} <= set(e)
            assert e["kind"] in {"verification", "ingest", "custody", "identity"}
        exp = c["expected"]
        assert set(exp) == {"rules", "correlation", "pending"}
        for r in exp["rules"]:
            assert set(r) == {"rule_id", "suppressed"}
            assert r["rule_id"].startswith("SEC-")
            assert isinstance(r["suppressed"], bool)
        assert {s["trace_id"]: s["correlation"] for s in c["steps"]} == exp["correlation"]
        assert exp["pending"] == 0
        # synthetic secret markers only ever appear in the sensitive_data class
        if c["scenario_class"] != "sensitive_data":
            blob = json.dumps(c)
            for marker in (
                "AKIAFAKE0",
                "FAKE-BEARER-0123456789",
                "FAKE SYNTHETIC PRIVATE",
                "password=FAKE-VALUE",
            ):
                assert marker not in blob, f"{c['case_id']}: leaked marker {marker}"


def test_corpus_unique_case_ids() -> None:
    ids = [c["case_id"] for c in CASES]
    assert len(set(ids)) == len(ids)


def test_sensitive_data_cases_carry_synthetic_markers() -> None:
    sens = [c for c in CASES if c["scenario_class"] == "sensitive_data"]
    assert len(sens) == 5
    for c in sens:
        assert c["secrets_markers"], "sensitive_data cases declare their markers"
        for m in c["secrets_markers"]:
            assert m["synthetic"] is True
            assert m["kind"] in {"aws", "bearer", "private_key", "password"}


def test_every_sec_rule_exercised_by_expected_findings() -> None:
    exercised = {r["rule_id"] for c in CASES for r in c["expected"]["rules"]}
    assert exercised == {f"SEC-{i:03d}" for i in range(1, 12)}


# ------------------------------------------------------------ determinism ----


def test_determinism_two_generations_byte_identical() -> None:
    first = _gen.corpus_bytes()
    second = _gen.corpus_bytes()
    assert first == second


def test_committed_corpus_matches_fresh_generation() -> None:
    assert CORPUS_PATH.read_bytes() == _gen.corpus_bytes()


def test_generator_is_shebang_runnable_and_deterministic_processwise() -> None:
    out1 = subprocess.run(
        [sys.executable, str(HERE / "generate_corpus.py")],
        check=True,
        capture_output=True,
        cwd=REPO_ROOT,
    )
    out2 = subprocess.run(
        [sys.executable, str(HERE / "generate_corpus.py")],
        check=True,
        capture_output=True,
        cwd=REPO_ROOT,
    )
    assert out1.stdout == out2.stdout


# ----------------------------------------------------------------- replay ----


def test_offline_replay_harness_report() -> None:
    results = _run.run_corpus(CONFIG)
    assert all(r["ok"] for r in results)


@pytest.mark.parametrize("case", CASES, ids=[c["case_id"] for c in CASES])
def test_case_matches_expectation(case: dict) -> None:
    result = _run.check_case(case, CONFIG)
    assert result["ok"] is True
