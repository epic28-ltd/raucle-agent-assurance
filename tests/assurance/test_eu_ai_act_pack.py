# SPDX-License-Identifier: Apache-2.0
"""H2 slice 1 tests: EU AI Act compliance pack v1 consistency.

Guards the contract between the pack document
(`docs/compliance/eu-ai-act-pack-v1.md`) and the crosswalk data
(`ops/assurance-profiles/crosswalk.json`): every control id the pack cites
must exist as an EU AI Act crosswalk row with the same status, every focus
area must have at least one row, and the validator self-check must stay
empty so no row drifts into claiming more than the evidence plane supports.
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
PACK_DOC = REPO_ROOT / "docs" / "compliance" / "eu-ai-act-pack-v1.md"

FOCUS_AREAS = [
    "logging and record-keeping",
    "transparency",
    "human oversight",
    "robustness",
]


def _eu_ai_act_rows() -> dict[str, dict]:
    return {row["control_id"]: row for row in CROSSWALK["rows"] if row["framework"] == "EU AI Act"}


def test_validator_self_check_stays_empty() -> None:
    assert validator.self_check(profiles=validator.load_profiles(), crosswalk=CROSSWALK) == []


def test_focus_areas_are_each_covered_by_crosswalk_rows() -> None:
    rows = _eu_ai_act_rows()
    for area in FOCUS_AREAS:
        section = re.search(rf"## Focus area .*: {re.escape(area)}", PACK_DOC.read_text())
        assert section is not None, f"pack doc has no section for focus area: {area}"
    # each focus area maps to at least one EU AI Act crosswalk row
    assert {
        "Art 12(1) logging",
        "Art 19 record-keeping of logs",
    } <= rows.keys(), "logging/record-keeping rows missing"
    assert {
        "Art 13(1)-13(3) transparency to deployers",
        "Art 50(1) transparency to users",
    } <= rows.keys(), "transparency rows missing"
    assert "Art 14 human oversight" in rows, "human oversight row missing"
    assert "Art 15(1) robustness and accuracy" in rows, "robustness row missing"


def test_pack_cited_controls_match_crosswalk_rows() -> None:
    rows = _eu_ai_act_rows()
    table_ids = set(re.findall(r"`(Art \d+[^`]*)`", PACK_DOC.read_text()))
    eu_ai_act_ids = set(rows)
    # every id the pack cites must be a real crosswalk row
    assert table_ids <= eu_ai_act_ids, f"pack cites unknown controls: {table_ids - eu_ai_act_ids}"
    # every EU AI Act crosswalk row must be cited by the pack (no silent rows)
    assert eu_ai_act_ids <= table_ids, (
        f"crosswalk rows not cited by pack: {eu_ai_act_ids - table_ids}"
    )


def test_pack_status_column_matches_crosswalk_statuses() -> None:
    rows = _eu_ai_act_rows()
    match = re.search(
        r"## Focus area [0-9]+: logging and record-keeping(.*?)## ",
        PACK_DOC.read_text(),
        re.S,
    )
    assert match is not None
    for control_id in re.findall(r"`(Art \d+[^`]*)`", match.group(1)):
        row = rows[control_id]
        if row["evidence_field"]:
            assert f"`{row['evidence_field']}`" in match.group(1) or row["status"] != "SUPPORTED"
        assert row["status"] in {"SUPPORTED", "PARTIAL", "UNSUPPORTED"}


def test_unsupported_rows_carry_honest_reasons() -> None:
    for row in _eu_ai_act_rows().values():
        if row["status"] == "UNSUPPORTED":
            assert row.get("evidence_field") is None
            assert row.get("unsat_reason", "").strip()
            assert row["unsat_reason"].split(" ")[0] not in {"TODO", "TBD"}
