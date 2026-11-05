# SPDX-License-Identifier: Apache-2.0
"""OV-8 AgentRunRecord schema + privacy-filtered fixture generator tests."""

from __future__ import annotations

import importlib.util
import json
import pathlib

import jsonschema

REPO = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO / "schemas" / "agent_run_record.schema.json"
RUNS_PATH = REPO / "services" / "investigation-ui" / "demo_data" / "runs.json"
INDEX_PATH = REPO / "services" / "investigation-ui" / "demo_data" / "synthetic_receipt_index.jsonl"


def _load_gen():
    spec = importlib.util.spec_from_file_location(
        "generate_fixtures", REPO / "tools" / "run_records" / "generate_fixtures.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_gen = _load_gen()
_SCHEMA = json.loads(SCHEMA_PATH.read_text())


def _generate():
    return _gen.generate(RUNS_PATH, INDEX_PATH)


def test_generated_fixtures_validate_against_schema():
    doc = _generate()
    validator_cls = jsonschema.validators.validator_for(_SCHEMA)
    validator = validator_cls(_SCHEMA)
    assert doc["records"], "expected at least one record from the demo runs"
    for record in doc["records"]:
        validator.validate(record)


def test_privacy_scan_forbidden_marker_in_payload_is_refused():
    # Any forbidden marker (raw JWS bytes marker, credential vocabulary,
    # conversation content vocabulary) must make generation refuse.
    for marker in ("eyJhbGciOiJFUzI1NiJ9", "api_key=AKIA000", "prompt_text"):
        doc = _generate()
        doc["records"][0]["smuggled"] = {"poison": marker}
        hits = _gen._refuse(doc)
        assert hits, f"expected refuse scan to catch {marker!r}"


def test_unknown_receipts_stay_unknown():
    # rule 3: valid is never inferred from missing data.
    doc = _generate()
    unknowns = [r for rec in doc["records"] for r in rec["receipts"] if r["decision"] == "unknown"]
    assert unknowns, "expected the demo data to exercise the unknown path"
    for receipt in unknowns:
        assert receipt["decision"] == "unknown"


def test_synthetic_receipts_carry_synthetic_marker():
    doc = _generate()
    marked = [
        r
        for rec in doc["records"]
        for r in rec["receipts"]
        if r["receipt_hash"].startswith("sha256:synth")
    ]
    assert marked, "expected synthetic demo receipts in the fixtures"
    for receipt in marked:
        assert receipt.get("synthetic") is True


def test_no_conversation_content_in_output():
    payload = json.dumps(_generate())
    for forbidden in ("jws", "eyJ", "oaa.note", "<script", "alert"):
        assert forbidden not in payload.lower().replace("jws ", "x"), forbidden


def test_generation_is_deterministic():
    first = json.dumps(_generate(), sort_keys=True)
    second = json.dumps(_generate(), sort_keys=True)
    assert first == second


def test_usage_metrics_count_receipts_consistently():
    doc = _generate()
    for record in doc["records"]:
        metrics = record["usage_metrics"]
        total = metrics["receipts_allow"] + metrics["receipts_deny"] + metrics["receipts_unknown"]
        assert total == metrics["receipts_total"] == len(record["receipts"])
