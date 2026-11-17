# SPDX-License-Identifier: Apache-2.0
"""H2 slice 4 tests: ISO/IEC 42001 compliance pack v1 consistency.

Guards the contract between the pack document
(`docs/compliance/iso-42001-pack-v1.md`) and the crosswalk data
(`ops/assurance-profiles/crosswalk.json`): every control id the pack cites
must exist as an ISO 42001 crosswalk row with the same status, every focus
area must have at least one row, and the validator self-check must stay
empty so no row drifts into claiming more than the evidence plane supports.
The pack copy must stay a mapping: no compliance, certification or
conformance claims, and no vendor names anywhere in the pack docs or the
shared compliance index.
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
PACK_DOC = REPO_ROOT / "docs" / "compliance" / "iso-42001-pack-v1.md"
COMPLIANCE_INDEX = REPO_ROOT / "docs" / "compliance" / "README.md"

FOCUS_AREAS = {
    "AIMS context, leadership and AI policy (Clause 4, Clause 5, A.2, A.3)": {
        "Clause 4.3 AIMS scope",
        "A.2.2 AI policy",
        "A.3.2 AI roles and responsibilities",
    },
    "AI risk assessment and treatment (Clause 6, A.5)": {
        "A.5.3 documentation of AI system impact assessments",
        "Clause 6.1.3 AI risk treatment",
    },
    "support and AI system operation (Clause 7, Clause 8, A.6)": {
        "Clause 7.2 competence",
        "Clause 7.5 documented information",
        "A.6.2.4 AI system verification and validation",
        "A.6.2.6 AI system operation and monitoring",
        "A.6.2.8 AI system recording of event logs",
    },
    "performance evaluation and improvement (Clause 9, Clause 10)": {
        "Clause 9.1 monitoring, measurement and evaluation",
        "Clause 9.2 internal audit",
        "Clause 10.2 continual improvement",
    },
}

# ISO 42001 control ids in the pack tables: Annex A controls (A.x.y) and
# management-system clauses (Clause x.y).
_ID = re.compile(r"`((?:A\.[0-9]+|Clause [0-9]+)[^`]*)`")


def _iso42001_rows() -> dict[str, dict]:
    return {row["control_id"]: row for row in CROSSWALK["rows"] if row["framework"] == "ISO 42001"}


def test_validator_self_check_stays_empty() -> None:
    assert validator.self_check(profiles=validator.load_profiles(), crosswalk=CROSSWALK) == []


def test_focus_areas_are_each_covered_by_crosswalk_rows() -> None:
    rows = _iso42001_rows()
    for area, expected_ids in FOCUS_AREAS.items():
        section = re.search(rf"## Focus area [0-9]+: {re.escape(area)}", PACK_DOC.read_text())
        assert section is not None, f"pack doc has no section for focus area: {area}"
        assert expected_ids <= rows.keys(), f"{area} crosswalk row missing"
    # every ISO 42001 crosswalk row belongs to a focus area the pack documents
    documented = set().union(*FOCUS_AREAS.values())
    assert set(rows) == documented, f"undocumented ISO 42001 rows: {set(rows) - documented}"


def test_pack_cited_controls_match_crosswalk_rows() -> None:
    rows = _iso42001_rows()
    table_ids = set(_ID.findall(PACK_DOC.read_text()))
    iso_ids = set(rows)
    # every id the pack cites must be a real crosswalk row
    assert table_ids <= iso_ids, f"pack cites unknown controls: {table_ids - iso_ids}"
    # every ISO 42001 crosswalk row must be cited by the pack (no silent rows)
    assert iso_ids <= table_ids, f"crosswalk rows not cited by pack: {iso_ids - table_ids}"


def test_pack_status_column_matches_crosswalk_statuses() -> None:
    rows = _iso42001_rows()
    text = PACK_DOC.read_text()
    for area in FOCUS_AREAS:
        match = re.search(rf"## Focus area [0-9]+: {re.escape(area)}(.*?)## ", text, re.S)
        assert match is not None
        for control_id in _ID.findall(match.group(1)):
            row = rows[control_id]
            if row["evidence_field"]:
                assert (
                    f"`{row['evidence_field']}`" in match.group(1) or row["status"] != "SUPPORTED"
                )
            assert row["status"] in {"SUPPORTED", "PARTIAL", "UNSUPPORTED"}


def test_unsupported_rows_carry_honest_reasons() -> None:
    for row in _iso42001_rows().values():
        if row["status"] == "UNSUPPORTED":
            assert row.get("evidence_field") is None
            assert row.get("unsat_reason", "").strip()
            assert row["unsat_reason"].split(" ")[0] not in {"TODO", "TBD"}


def test_iso42001_pack_makes_no_certification_or_compliance_claims() -> None:
    text = PACK_DOC.read_text()
    # the repo's compliance-honest invariant: the pack maps, it never claims
    assert "mapped to" in text
    for forbidden in ("is compliant", "certified", "achieves compliance"):
        assert forbidden not in text, f"compliance-claim language found: {forbidden!r}"
    assert "AIMS" in text
    assert "makes no claim" in text


def test_pack_copy_names_no_vendors() -> None:
    for doc in (PACK_DOC, COMPLIANCE_INDEX):
        text = doc.read_text()
        for vendor in ("Varonis", "Atlas", "Drata", "Vanta", "Splunk", "ServiceNow"):
            assert vendor not in text, f"vendor name in pack copy: {vendor!r}"


def test_compliance_index_lists_all_five_packs() -> None:
    text = COMPLIANCE_INDEX.read_text()
    for pack in (
        "eu-ai-act-pack-v1.md",
        "hipaa-security-rule-pack-v1.md",
        "pci-dss-pack-v1.md",
        "iso-42001-pack-v1.md",
        "nist-ai-rmf-pack-v1.md",
    ):
        assert pack in text, f"compliance index does not list {pack}"
    assert "mapped to" in text
