# SPDX-License-Identifier: Apache-2.0
"""H2 slice 2 tests: HIPAA Security Rule compliance pack v1 consistency.

Guards the contract between the pack document
(`docs/compliance/hipaa-security-rule-pack-v1.md`) and the crosswalk data
(`ops/assurance-profiles/crosswalk.json`): every control id the pack cites
must exist as a HIPAA crosswalk row with the same status, every 164.312
focus area must have at least one row, and the validator self-check must
stay empty so no row drifts into claiming more than the evidence plane
supports.
"""

from __future__ import annotations

import importlib.util
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
PACK_DOC = REPO_ROOT / "docs" / "compliance" / "hipaa-security-rule-pack-v1.md"

FOCUS_AREAS = {
    "audit controls": {"164.312(b) audit controls"},
    "integrity": {"164.312(c)(1) integrity"},
    "access control": {"164.312(a)(1) access control"},
    "transmission security": {"164.312(e)(1) transmission security"},
}


def _hipaa_rows() -> dict[str, dict]:
    return {row["control_id"]: row for row in CROSSWALK["rows"] if row["framework"] == "HIPAA"}


def test_validator_self_check_stays_empty() -> None:
    assert validator.self_check(profiles=validator.load_profiles(), crosswalk=CROSSWALK) == []


def test_focus_areas_are_each_covered_by_crosswalk_rows() -> None:
    rows = _hipaa_rows()
    for area, expected_ids in FOCUS_AREAS.items():
        section = re.search(rf"## Focus area [0-9]+: {re.escape(area)}", PACK_DOC.read_text())
        assert section is not None, f"pack doc has no section for focus area: {area}"
        assert expected_ids <= rows.keys(), f"{area} crosswalk row missing"
    # every HIPAA crosswalk row belongs to a focus area the pack documents
    documented = set().union(*FOCUS_AREAS.values())
    assert set(rows) == documented, f"undocumented HIPAA rows: {set(rows) - documented}"


def test_pack_cited_controls_match_crosswalk_rows() -> None:
    rows = _hipaa_rows()
    table_ids = set(re.findall(r"`(164\.312[^`]*)`", PACK_DOC.read_text()))
    hipaa_ids = set(rows)
    # every id the pack cites must be a real crosswalk row
    assert table_ids <= hipaa_ids, f"pack cites unknown controls: {table_ids - hipaa_ids}"
    # every HIPAA crosswalk row must be cited by the pack (no silent rows)
    assert hipaa_ids <= table_ids, f"crosswalk rows not cited by pack: {hipaa_ids - table_ids}"


def test_pack_status_column_matches_crosswalk_statuses() -> None:
    rows = _hipaa_rows()
    text = PACK_DOC.read_text()
    for area in FOCUS_AREAS:
        match = re.search(rf"## Focus area [0-9]+: {re.escape(area)}(.*?)## ", text, re.S)
        assert match is not None
        for control_id in re.findall(r"`(164\.312[^`]*)`", match.group(1)):
            row = rows[control_id]
            if row["evidence_field"]:
                assert (
                    f"`{row['evidence_field']}`" in match.group(1) or row["status"] != "SUPPORTED"
                )
            assert row["status"] in {"SUPPORTED", "PARTIAL", "UNSUPPORTED"}


def test_unsupported_rows_carry_honest_reasons() -> None:
    for row in _hipaa_rows().values():
        if row["status"] == "UNSUPPORTED":
            assert row.get("evidence_field") is None
            assert row.get("unsat_reason", "").strip()
            assert row["unsat_reason"].split(" ")[0] not in {"TODO", "TBD"}


def test_hipaa_pack_makes_no_phi_or_compliance_claims() -> None:
    text = PACK_DOC.read_text()
    # the repo's compliance-honest invariant: the pack maps, it never claims
    assert "mapped to" in text
    for forbidden in ("is compliant", "certified", "achieves compliance"):
        assert forbidden not in text, f"compliance-claim language found: {forbidden!r}"
    assert "no PHI" in text or "no claim" in text
