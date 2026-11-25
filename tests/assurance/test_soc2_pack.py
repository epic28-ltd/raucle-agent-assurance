# SPDX-License-Identifier: Apache-2.0
"""SOC 2 TSC mapping v1 crosswalk, export and claim-boundary tests."""

from __future__ import annotations

import importlib.util
import json
import pathlib
import re

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "oaa_assurance_profiles_validator",
    REPO_ROOT / "ops" / "assurance-profiles" / "validator.py",
)
assert _SPEC is not None
validator = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(validator)  # type: ignore[union-attr]

CROSSWALK = validator.load_crosswalk()
PACK_DOC = REPO_ROOT / "docs" / "compliance" / "soc2-pack-v1.md"
COMPLIANCE_INDEX = REPO_ROOT / "docs" / "compliance" / "README.md"
FRAMEWORK = "SOC 2"


def _rows() -> dict[str, dict]:
    return {row["control_id"]: row for row in CROSSWALK["rows"] if row["framework"] == FRAMEWORK}


def _table(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith("| Crosswalk control |"):
            continue
        assert "| Status |" in line
        assert lines[i + 1].startswith("| ---")
        j = i + 2
        while j < len(lines) and lines[j].startswith("| `"):
            cells = [cell.strip() for cell in lines[j].strip().strip("|").split("|")]
            control_id = cells[0].strip("`")
            assert control_id not in out
            out[control_id] = cells[2]
            j += 1
    return out


def test_validator_self_check_stays_empty() -> None:
    assert validator.self_check(profiles=validator.load_profiles(), crosswalk=CROSSWALK) == []


def test_full_criteria_inventory_is_present() -> None:
    expected = (
        {
            f"CC{number}.{index}"
            for number, count in [
                (1, 5),
                (2, 3),
                (3, 4),
                (4, 2),
                (5, 3),
                (6, 8),
                (7, 5),
                (8, 1),
                (9, 2),
            ]
            for index in range(1, count + 1)
        }
        | {f"A1.{index}" for index in range(1, 4)}
        | {f"C1.{index}" for index in range(1, 3)}
        | {f"PI1.{index}" for index in range(1, 6)}
        | {f"P1.{index}" for index in range(1, 9)}
    )
    ids = set(_rows())
    normalised = {
        match.group(1) if (match := re.match(r"^(CC[1-9]\.[1-9])", control_id)) else control_id
        for control_id in ids
    }
    assert normalised == expected


def test_pack_table_matches_crosswalk_statuses_bidirectionally() -> None:
    rows = _rows()
    pack_text = PACK_DOC.read_text()
    table = _table(pack_text)
    assert set(table) == set(rows)
    for control_id, status in table.items():
        assert status in {"SUPPORTED", "PARTIAL", "UNSUPPORTED"}
        assert status == rows[control_id]["status"]
        if status == "SUPPORTED":
            assert rows[control_id]["evidence_field"] in pack_text


def test_unsupported_rows_have_explicit_reasons() -> None:
    for row in _rows().values():
        if row["status"] == "UNSUPPORTED":
            assert row.get("evidence_field") is None
            assert row.get("unsat_reason", "").strip()


def test_existing_soc2_governance_profile_references_remain_valid() -> None:
    required = validator.load_profiles()["profiles"]["regulated"]["required_controls"]
    for control_id in (
        "CC7.1 configuration monitoring",
        "CC9.1 access risk mitigation",
    ):
        assert f"SOC 2:{control_id}" in required
        assert control_id in _rows()
    # CC7.2 remains in the crosswalk but is not a required regulated-profile row.
    assert "CC7.2 anomaly detection" in _rows()


def test_export_contains_soc2_controls_and_honest_gaps() -> None:
    spec = importlib.util.spec_from_file_location(
        "grc_export", REPO_ROOT / "tools" / "grc_export" / "export.py"
    )
    assert spec is not None
    exporter = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(exporter)  # type: ignore[union-attr]
    packet = json.loads(
        (REPO_ROOT / "ops" / "assurance-profiles" / "fixtures" / "green.json").read_text()
    )
    graph = exporter.build_graph(CROSSWALK, packet)
    nodes = {
        node["control_id"]: node
        for node in graph["nodes"]
        if node["kind"] == "control" and node["framework"] == FRAMEWORK
    }
    assert set(nodes) == set(_rows())
    for control_id, row in _rows().items():
        if row["status"] == "UNSUPPORTED":
            assert nodes[control_id]["evidence_field"] is None


def test_pack_avoids_attestation_and_compliance_claims() -> None:
    pack_text = PACK_DOC.read_text().lower()
    assert "this pack makes no claim" in pack_text
    assert "not a soc 2 report" in pack_text
    assert "not a soc 2 report, audit opinion" in pack_text


def test_compliance_index_lists_soc2_pack() -> None:
    assert "soc2-pack-v1.md" in COMPLIANCE_INDEX.read_text()
