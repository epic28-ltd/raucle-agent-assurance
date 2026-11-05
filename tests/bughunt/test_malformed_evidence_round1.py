# SPDX-License-Identifier: Apache-2.0
"""BUG-HUNT round 1: malformed-evidence regressions across the evidence readers.

Each test reproduces a crash found by adversarial input fuzzing:
- prebind.load_receipt_index crashed on a garbage/JSON-decodable non-object
  line, and prebind_indicators crashed with KeyError/AttributeError on a
  receipt row missing receipt_hash (the Perch-class reader asymmetry).
- tools/run_records/generate_fixtures.load_receipt_index crashed on garbage /
  null lines.
- correlation.load_receipt_index crashed on garbage/null/missing-field lines.
- release_compiler.validate_run_set crashed with AttributeError instead of the
  named schema error when a record was not an object.
- profiles-crosswalk validate() crashed on a non-object packet and the CLI
  crashed with a traceback on a missing/malformed packet file.
Every case here must exercise the fixed behavior: named skip or named
ValueError, never an unhandled exception class.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]


# ----------------------------------------------------------- prebind ------
sys.path.insert(0, str(REPO / "services" / "prebind" / "src"))

from oaa_prebind.derive import load_receipt_index, prebind_indicators  # noqa: E402


def _write(tmp_path: pathlib.Path, content: str) -> pathlib.Path:
    p = tmp_path / "receipts.jsonl"
    p.write_text(content, encoding="utf-8")
    return p


GOOD = {
    "receipt_hash": "h1",
    "provenance": "gate-1",
    "trace_id": "t1",
    "decision": "deny",
    "schema_version": "provenance-receipt/v1",
}


def test_prebind_reader_garbage_line_is_named_valueerror(tmp_path):
    path = _write(tmp_path, json.dumps(GOOD) + "\n" + '{"receipt_hash":\n')
    with pytest.raises(ValueError, match="not a JSON object"):
        load_receipt_index(path)


def test_prebind_reader_null_line_is_named_valueerror(tmp_path):
    path = _write(tmp_path, "null\n")
    with pytest.raises(ValueError, match="NoneType, not an object"):
        load_receipt_index(path)


def test_prebind_receipt_without_hash_is_named_skip_not_keyerror():
    # Was: KeyError 'receipt_hash' from by_hash grouping.
    result = prebind_indicators([{"decision": "deny"}])
    assert result["counts"]["refused"] == 1  # decision still counts
    assert any(a.startswith("malformed_receipt_row:") for a in result["anomalies"])


def test_prebind_null_row_is_named_skip_not_typeerror():
    # Was: TypeError 'NoneType' object is not subscriptable.
    result = prebind_indicators([None, dict(GOOD)])
    assert result["counts"]["refused"] == 1
    assert result["anomalies"] == ["malformed_receipt_row:0"]


def test_prebind_hashless_rows_are_excluded_from_grouping():
    # Two keyable rows share a trace: ambiguous_trace fires. A hashless row
    # sharing that trace (or any other) contributes no grouping and no crash.
    dup = dict(GOOD, trace_id="t2", receipt_hash="h2")
    keyable_twin = dict(dup)
    hashless = {"decision": "allow", "trace_id": "t2"}
    result = prebind_indicators([dup, keyable_twin, hashless])
    # identical twins are duplicate receipts, not an ambiguous trace (the
    # trace only ever cites one hash); the hashless row is named, not crashed.
    assert result["anomalies"] == sorted(
        {"duplicate_receipt:h2", "legacy_schema:None", "malformed_receipt_row:2"}
    )


# ------------------------------------------------- run-record generator ---
def _load_gen():
    spec = importlib.util.spec_from_file_location(
        "generate_fixtures", REPO / "tools" / "run_records" / "generate_fixtures.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_run_record_reader_garbage_line_is_named_valueerror(tmp_path):
    p = tmp_path / "idx.jsonl"
    p.write_text('{"receipt_hash": "a"}\ngarbage\n', encoding="utf-8")
    with pytest.raises(ValueError, match="not a JSON object"):
        _load_gen().load_receipt_index(p)


def test_run_record_reader_null_line_is_named_valueerror(tmp_path):
    p = tmp_path / "idx.jsonl"
    p.write_text("null\n", encoding="utf-8")
    with pytest.raises(ValueError, match="NoneType, not an object"):
        _load_gen().load_receipt_index(p)


# ------------------------------------------------------------ correlation -
sys.path.insert(0, str(REPO / "services" / "correlation" / "src"))

import oaa_correlation.core as cc  # noqa: E402


def test_correlation_reader_garbage_line_is_named_valueerror(tmp_path):
    p = tmp_path / "idx.jsonl"
    p.write_text("garbage\n", encoding="utf-8")
    with pytest.raises(ValueError, match="not a JSON object"):
        cc.load_receipt_index(p, read_only=False)


def test_correlation_reader_null_line_is_named_typeerror(tmp_path):
    p = tmp_path / "idx.jsonl"
    p.write_text("null\n", encoding="utf-8")
    with pytest.raises(TypeError, match="NoneType, not an object"):
        cc.load_receipt_index(p, read_only=False)


def test_correlation_reader_missing_hash_is_named_valueerror(tmp_path):
    p = tmp_path / "idx.jsonl"
    p.write_text(json.dumps({"event_time": "2026-11-05T00:00:00+00:00"}) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no receipt_hash field"):
        cc.load_receipt_index(p, read_only=False)


# ------------------------------------------------------ release compiler ---
def _load_rc():
    spec = importlib.util.spec_from_file_location(
        "release_compile", REPO / "tools" / "release_compiler" / "compile.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_release_compiler_non_object_record_is_named_schema_error():
    # Was: AttributeError 'list' object has no attribute 'get'.
    with pytest.raises(ValueError, match="agent_run_record schema"):
        _load_rc().validate_run_set(
            {"schema_version": "agent_run_record/v1", "records": [[1, 2, 3]]}
        )


# ------------------------------------------------- crosswalk validator ----
sys.path.insert(0, str(REPO / "ops" / "assurance-profiles"))

import validator as xval  # noqa: E402

_profiles = xval.load_profiles()


def test_crosswalk_validator_non_object_packet_is_named_fail():
    # Was: AttributeError 'list' object has no attribute 'get'.
    result = xval.validate([1, 2, 3], "basic", profiles=_profiles, crosswalk={"rows": []})
    assert result["verdict"] == "FAIL"
    assert result["checks"][0]["check_id"] == "packet:shape"


def test_crosswalk_validator_cli_missing_packet_is_named_error(capsys, tmp_path):
    assert xval.main(["--packet", str(tmp_path / "nope.json")]) == 1
    assert "cannot load packet" in capsys.readouterr().err


def test_crosswalk_validator_cli_malformed_packet_is_named_error(capsys, tmp_path):
    p = tmp_path / "packet.json"
    p.write_text("not json{", encoding="utf-8")
    assert xval.main(["--packet", str(p)]) == 1
    assert "cannot load packet" in capsys.readouterr().err
