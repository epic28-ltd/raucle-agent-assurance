# SPDX-License-Identifier: Apache-2.0
"""OV-7 Agent Process Expectations schema + validator tests."""

from __future__ import annotations

import importlib.util
import pathlib

import yaml

REPO = pathlib.Path(__file__).resolve().parents[2]
EXAMPLE = REPO / "examples" / "expectations" / "example-expectations.yaml"
SCHEMA = (REPO / "schemas" / "agent_process_expectations.schema.json").read_text()


def _load_validator():
    spec = importlib.util.spec_from_file_location(
        "validate_expectations", REPO / "tools" / "expectations" / "validate.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_v = _load_validator()


def _doc():
    return yaml.safe_load(EXAMPLE.read_text())


def test_main_exit_zero_on_valid_document():
    assert _v.main([str(EXAMPLE)]) == 0


def test_main_exit_nonzero_with_message_on_poisoned_document(tmp_path):
    poisoned = tmp_path / "poisoned.yaml"
    doc = _doc()
    doc["cases"][0]["boundaries"]["providers"].append("unsanctioned")
    poisoned.write_text(yaml.safe_dump(doc))
    assert _v.main([str(poisoned)]) == 1


def test_example_document_is_valid():
    assert _v.validate_document(_doc()) == []


def test_schema_rejects_boundary_widening():
    doc = _doc()
    # A provider the case set never sanctioned must be refused: closed set.
    doc["cases"][0]["boundaries"]["providers"].append("other-provider")
    problems = _v.validate_document(doc)
    assert problems, "expected provider boundary widening to be refused"


def test_schema_rejects_unknown_mapped_into_pass():
    doc = _doc()
    doc["cases"][0]["expected_outcome"]["gate_decisions"].append("unknown")
    problems = _v.validate_document(doc)
    assert problems, "unknown must not be a selectable expected gate decision"


def test_negative_budget_is_refused():
    doc = _doc()
    doc["cases"][0]["budgets"]["max_tool_calls"] = -1
    problems = _v.validate_document(doc)
    assert any("budgets/max_tool_calls" in pointer for pointer, _ in problems)


def test_privileged_budget_without_review_route_is_refused():
    doc = _doc()
    case = doc["cases"][0]
    case["budgets"]["max_privileged_tool_calls"] = 3
    del case["human_review"]
    problems = _v.validate_document(doc)
    assert any("no human_review route" in message for _, message in problems)


def test_missing_receipt_hash_evidence_is_refused_precisely():
    doc = _doc()
    doc["cases"][0]["evidence_links"] = [{"kind": "trace-id", "ref": "t-sim-amb"}]
    problems = _v.validate_document(doc)
    assert any("no receipt-hash evidence link" in message for _, message in problems)


def test_receipt_hash_ref_must_look_like_a_receipt():
    doc = _doc()
    doc["cases"][0]["evidence_links"][0]["ref"] = "not-a-receipt"
    problems = _v.validate_document(doc)
    assert any("must start with sha256:" in message for _, message in problems)


def test_duplicate_case_id_is_refused_with_context():
    doc = _doc()
    doc["cases"].append(dict(doc["cases"][0]))
    problems = _v.validate_document(doc)
    assert any("duplicate case_id" in message for _, message in problems)


def test_malformed_document_reports_a_precise_error():
    problems = _v.validate_document({"schema_version": "wrong", "cases": []})
    assert any("schema_version" in pointer for pointer, _ in problems)
