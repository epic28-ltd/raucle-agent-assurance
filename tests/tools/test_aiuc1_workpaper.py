# SPDX-License-Identifier: Apache-2.0
"""N7 tests: AIUC-1 crosswalk rows + workpapers/v1 export.

Covers: crosswalk rows are derivation-tagged and verbatim-cited, workpaper
export is deterministic and schema-valid, evidence nodes are hash-only, and
honest-UNSUPPORTED rows never gain evidence or papered-over gaps.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

jsonschema = pytest.importorskip("jsonschema")

REPO = pathlib.Path(__file__).resolve().parents[2]
CROSSWALK = REPO / "ops" / "assurance-profiles" / "crosswalk.json"
SCHEMA = REPO / "schemas" / "aiuc1_workpaper.schema.json"
GREEN = REPO / "ops" / "assurance-profiles" / "fixtures" / "green.json"
RH1 = "sha256:" + "a" * 64
RH2 = "sha256:" + "b" * 64


def _load(name):
    spec = importlib.util.spec_from_file_location(name, REPO / "tools" / "grc_export" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


exporter = _load("export")
workpaper = _load("workpaper")
CROSSWALK_DATA = json.loads(CROSSWALK.read_text())
GREEN_DATA = json.loads(GREEN.read_text())


def _aiuc1_rows():
    return [r for r in CROSSWALK_DATA["rows"] if r["framework"] == "AIUC-1"]


def _build(packet):
    return workpaper.build_workpapers(CROSSWALK_DATA, packet, exporter._dotted_lookup)


# ------------------------------------------------------- crosswalk derivation


def test_aiuc1_rows_exist_and_are_derivation_tagged():
    rows = _aiuc1_rows()
    assert len(rows) == 8
    families = {r["family_heading"] for r in rows}
    assert families == {"E. Accountability", "D. Reliability"}
    for row in rows:
        assert row["derivation"] == "derived"
        assert row["source_heading"] and row["source_url"].startswith("https://standard.aiuc-1.com/")
        assert row["control_text"] and row["control_text"] == row["control_text"].strip()


def test_every_aiuc1_row_cites_its_heading_verbatim():
    # verbatim-citation presence: the heading id appears inside the verbatim
    # source citation fields and the citation is present, not paraphrased.
    for row in _aiuc1_rows():
        assert row["source_heading"] in row["control_id"]  # e.g. "E004: Assign accountability"
        assert len(row["control_text"]) > len(row["source_heading"])  # full text, not just the heading
        assert row["source_url"].rstrip(".md") in json.dumps(row)


def test_aiuc1_workpaper_rows_have_full_citations_for_export():
    workpaper.export_rows(CROSSWALK_DATA)  # named failure if any citation field is missing


# ------------------------------------------------------------- export + schema


def _green_with_receipts():
    packet = json.loads(GREEN.read_text())
    packet["receipt_chain"]["receipt_hashes"] = [RH2, RH1]  # unsorted on purpose
    return packet


def test_output_validates_against_the_workpaper_schema():
    doc = _build(_green_with_receipts())
    jsonschema.validate(doc, json.loads(SCHEMA.read_text()))
    assert json.loads(workpaper.render(doc)) == doc


def test_deterministic_byte_identical_output(tmp_path):
    packet = _green_with_receipts()
    p = tmp_path / "packet.json"
    p.write_text(json.dumps(packet))
    out1, out2 = tmp_path / "w1.json", tmp_path / "w2.json"
    assert (
        exporter.main(["--profile", "aiuc1", "--packet", str(p), "--out", str(out1)]) == 0
    )
    assert (
        exporter.main(["--profile", "aiuc1", "--packet", str(p), "--out", str(out2)]) == 0
    )
    assert out1.read_text() == out2.read_text()
    doc = json.loads(out1.read_text())
    assert doc["kind"] == "workpapers" and doc["schema_version"] == 1
    assert doc["inputs"]["workpaper_count"] == len(doc["workpapers"]) == 8
    # no wall-clock / volatile data
    assert "timestamp" not in json.dumps(doc)
    assert all(".py" not in json.dumps(wp) for wp in doc["workpapers"])


def test_workpaper_carries_verbatim_control_text_and_citation():
    doc = _build(_green_with_receipts())
    wp = next(w for w in doc["workpapers"] if w["control_id"] == "D003: Restrict unsafe tool calls")
    assert wp["control_text"].startswith(
        "Implement safeguards or technical controls to prevent tool calls"
    )
    assert wp["source_heading"] == "D003: Restrict unsafe tool calls"
    assert wp["derivation"] == "derived"
    assert wp["auditor_notes"]["derivation_note"]


def test_evidence_nodes_are_hash_only():
    for packet in (_green_with_receipts(), None):
        doc = _build(packet)
        for wp in doc["workpapers"]:
            for node in wp["evidence"]:
                # never carries a non-hash value field
                for key in node:
                    if key in ("hash", "value_sha256", "packet_sha256"):
                        assert node[key].startswith("sha256:")
                        assert len(node[key]) == 71
        # no signed payload leakage anywhere in the document
        full = json.dumps(doc)
        assert "jws" not in full and "eyJ" not in full
        assert "denial" not in full


def test_honest_unsupported_workpapers_have_no_evidence_beyond_the_packet_digest():
    doc = _build(_green_with_receipts())
    unsupported = [w for w in doc["workpapers"] if w["status"] == "UNSUPPORTED"]
    assert unsupported, "no status inflation: the AIUC-1 rows must include honest gaps"
    for wp in unsupported:
        # no evidence_field, no evidence-field digest; the packet digest (and
        # the receipt chain it names) travel with every workpaper as boundary
        # evidence, but they satisfy no UNSUPPORTED control.
        assert wp["evidence_field"] is None
        kinds = {e["kind"] for e in wp["evidence"]}
        assert "evidence_field_digest" not in kinds
        assert "evidence_field_digest" not in json.dumps(wp)
        assert wp["auditor_notes"]["gaps"] == [wp["auditor_notes"]["status_reason"]]
        assert wp["auditor_notes"]["status_reason"]


def test_honest_workpaper_status_per_row_against_shipped_machinery():
    doc = _build(_green_with_receipts())
    by_id = {w["control_id"]: w for w in doc["workpapers"]}
    assert by_id["E015: Log AI system activity"]["status"] == "SUPPORTED"
    assert by_id["D003: Restrict unsafe tool calls"]["status"] == "SUPPORTED"
    assert by_id["E004: Assign accountability"]["status"] == "PARTIAL"
    assert by_id["E001: AI failure plan for security breaches"]["status"] == "UNSUPPORTED"
    assert by_id["D001: Prevent hallucinated outputs"]["status"] == "UNSUPPORTED"
    assert by_id["E018: Third-party testing for accountability risk"]["status"] == "UNSUPPORTED"
    # PARTIAL names its scoping limitation; SUPPORTED names no gap
    assert by_id["E004: Assign accountability"]["auditor_notes"]["gaps"]
    assert by_id["D003: Restrict unsafe tool calls"]["auditor_notes"]["gaps"] == []


def test_supported_workpaper_binds_digest_evidence_from_the_packet():
    doc = _build(_green_with_receipts())
    wp = next(w for w in doc["workpapers"] if w["control_id"] == "E015: Log AI system activity")
    kinds = {e["kind"] for e in wp["evidence"]}
    assert kinds == {"packet", "evidence_field_digest", "receipt"}
    digests = [e for e in wp["evidence"] if e["kind"] == "evidence_field_digest"]
    assert digests[0]["packet_field"] == "receipt_chain.receipt_hashes"
    hashes = sorted(e["hash"] for e in wp["evidence"] if e["kind"] == "receipt")
    assert hashes == [RH1, RH2]  # sorted for determinism, hash only


def test_partial_evidence_field_absent_from_packet_degrades_honestly():
    packet = _green_with_receipts()
    packet.pop("coverage")  # E009 PARTIAL row cites coverage.unverified_tools
    doc = _build(packet)
    wp = next(w for w in doc["workpapers"] if w["control_id"] == "E009: Monitor third-party access")
    assert wp["status"] == "PARTIAL"  # status never inferred up or down
    assert "evidence_field_digest" not in json.dumps(wp)  # field absent: no digest, not a fake one
    assert wp["auditor_notes"]["gaps"] == [wp["auditor_notes"]["status_reason"]]


def test_unexportable_rows_are_named_failures():
    bad = {"version": 1, "rows": [{"framework": "AIUC-1", "control_id": "X", "status": "SUPPORTED"}]}
    with pytest.raises(workpaper.WorkpaperError, match="verbatim citation fields"):
        workpaper.export_rows(bad)
    with pytest.raises(workpaper.WorkpaperError, match="unknown workpaper profile"):
        workpaper.export_rows(CROSSWALK_DATA, profile="nist")
