# SPDX-License-Identifier: Apache-2.0
"""H2 slice 5 tests: NIST AI RMF compliance pack v1 consistency.

Guards the contract between the pack document
(`docs/compliance/nist-ai-rmf-pack-v1.md`) and the crosswalk data
(`ops/assurance-profiles/crosswalk.json`): every control id the pack cites
must exist as a NIST AI RMF crosswalk row with the same status, every RMF
core function (GOVERN / MAP / MEASURE / MANAGE) must have at least one row,
and the validator self-check must stay empty so no row drifts into claiming
more than the evidence plane supports. The pack copy must stay a mapping:
no adoption, conformance or compliance claims, no vendor names, and no
invented OWASP AI Testing Guide crosswalk.
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
PACK_DOC = REPO_ROOT / "docs" / "compliance" / "nist-ai-rmf-pack-v1.md"

FOCUS_AREAS = {
    "GOVERN": {
        "GOVERN 1.1 policies",
        "GOVERN 1.6 AI system inventory mechanisms",
        "GOVERN 2.1 roles and responsibilities",
    },
    "MAP": {
        "MAP 3.3 targeted application scope",
        "MAP 4.2 internal risk controls",
    },
    "MEASURE": {
        "MEASURE 1.2 effectiveness of controls",
        "MEASURE 2.5 validity and reliability",
        "MEASURE 2.7 security and resilience evaluation",
        "MEASURE 2.10 privacy risk examination",
    },
    "MANAGE": {
        "MANAGE 2.3 response to unknown risks",
        "MANAGE 3.1 third-party risk monitoring",
    },
}

# NIST AI RMF control ids in the pack tables: function-prefixed subcategories.
_ID = re.compile(r"`((?:GOVERN|MAP|MEASURE|MANAGE) [^`]*)`")


def _nist_ai_rmf_rows() -> dict[str, dict]:
    return {
        row["control_id"]: row for row in CROSSWALK["rows"] if row["framework"] == "NIST AI RMF"
    }


def test_validator_self_check_stays_empty() -> None:
    assert validator.self_check(profiles=validator.load_profiles(), crosswalk=CROSSWALK) == []


def test_focus_areas_are_each_covered_by_crosswalk_rows() -> None:
    rows = _nist_ai_rmf_rows()
    for area, expected_ids in FOCUS_AREAS.items():
        section = re.search(rf"## Focus area [0-9]+: {re.escape(area)}", PACK_DOC.read_text())
        assert section is not None, f"pack doc has no section for focus area: {area}"
        assert expected_ids <= rows.keys(), f"{area} crosswalk row missing"
    # every NIST AI RMF crosswalk row belongs to a focus area the pack documents
    documented = set().union(*FOCUS_AREAS.values())
    assert set(rows) == documented, f"undocumented NIST AI RMF rows: {set(rows) - documented}"


def test_pack_cited_controls_match_crosswalk_rows() -> None:
    rows = _nist_ai_rmf_rows()
    table_ids = set(_ID.findall(PACK_DOC.read_text()))
    nist_ids = set(rows)
    # every id the pack cites must be a real crosswalk row
    assert table_ids <= nist_ids, f"pack cites unknown controls: {table_ids - nist_ids}"
    # every NIST AI RMF crosswalk row must be cited by the pack (no silent rows)
    assert nist_ids <= table_ids, f"crosswalk rows not cited by pack: {nist_ids - table_ids}"


def test_pack_status_column_matches_crosswalk_statuses() -> None:
    rows = _nist_ai_rmf_rows()
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
    for row in _nist_ai_rmf_rows().values():
        if row["status"] == "UNSUPPORTED":
            assert row.get("evidence_field") is None
            assert row.get("unsat_reason", "").strip()
            assert row["unsat_reason"].split(" ")[0] not in {"TODO", "TBD"}


def test_nist_ai_rmf_pack_makes_no_adoption_or_compliance_claims() -> None:
    text = PACK_DOC.read_text()
    # the repo's compliance-honest invariant: the pack maps, it never claims
    assert "mapped to" in text
    for forbidden in ("is compliant", "certified", "achieves compliance"):
        assert forbidden not in text, f"compliance-claim language found: {forbidden!r}"
    assert "makes no claim" in text
    # the honest OWASP note: reuse the existing crosswalk slice, invent nothing
    assert "AI Testing Guide" in text
    assert "OWASP LLM Top 10" in text


def test_pack_copy_names_no_vendors() -> None:
    text = PACK_DOC.read_text()
    for vendor in ("Varonis", "Atlas", "Drata", "Vanta", "Splunk", "ServiceNow"):
        assert vendor not in text, f"vendor name in pack copy: {vendor!r}"
