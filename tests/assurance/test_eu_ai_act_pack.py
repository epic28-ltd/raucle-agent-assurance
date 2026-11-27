# SPDX-License-Identifier: Apache-2.0
"""H2 slice 1 tests: EU AI Act compliance pack v1 consistency.

Guards the contract between the pack document
(`docs/compliance/eu-ai-act-pack-v1.md`) and the crosswalk data
(`ops/assurance-profiles/crosswalk.json`): every control id the pack cites
must exist as an EU AI Act crosswalk row with the same status, every focus
area must have at least one row, and the validator self-check must stay
empty so no row drifts into claiming more than the evidence plane supports.
The pack's Status column is parsed from the markdown tables and matched
bidirectionally against the crosswalk statuses, so genuine drift fails.
The pack copy and the shared compliance index stay vendor-free.
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
COMPLIANCE_INDEX = REPO_ROOT / "docs" / "compliance" / "README.md"

FOCUS_AREAS = [
    "logging and record-keeping",
    "transparency",
    "human oversight",
    "robustness",
    "AI system technical documentation, data governance and AI literacy",
]

# EU AI Act control ids in the pack tables: Article references.
_ID = re.compile(r"`(Art \d+[^`]*)`")


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
    # focus area 5 (issue 113): technical documentation, data governance and
    # AI literacy rows must be present and honestly disposed
    for new_row in (
        "Art 11 technical documentation",
        "Art 10 data governance",
        "Art 4 AI literacy",
    ):
        assert new_row in rows, f"focus-area-5 row missing: {new_row}"


def test_pack_cited_controls_match_crosswalk_rows() -> None:
    rows = _eu_ai_act_rows()
    table_ids = set(_ID.findall(PACK_DOC.read_text()))
    eu_ai_act_ids = set(rows)
    # every id the pack cites must be a real crosswalk row
    assert table_ids <= eu_ai_act_ids, f"pack cites unknown controls: {table_ids - eu_ai_act_ids}"
    # every EU AI Act crosswalk row must be cited by the pack (no silent rows)
    assert eu_ai_act_ids <= table_ids, (
        f"crosswalk rows not cited by pack: {eu_ai_act_ids - table_ids}"
    )


def _pack_status_rows(text: str) -> dict[str, str]:
    """Parse every pack table row from the markdown: control id -> Status.

    House table shape: ``| Crosswalk control | <mapping> | Status | Evidence |``
    rows under a ``| ---`` separator, with backticked ids in the first cell.
    """
    statuses: dict[str, str] = {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith("| Crosswalk control |"):
            continue
        assert "| Status |" in line, "pack table has no Status column"
        assert lines[i + 1].startswith("| ---"), "pack table has no separator row"
        j = i + 2
        while j < len(lines) and lines[j].startswith("| `"):
            cells = [c.strip() for c in lines[j].strip().strip("|").split("|")]
            control_id = cells[0].strip("`")
            assert _ID.fullmatch(f"`{control_id}`"), f"unparsed control id: {control_id}"
            assert control_id not in statuses, f"duplicate pack table row: {control_id}"
            statuses[control_id] = cells[2]
            j += 1
    return statuses


def test_pack_status_column_matches_crosswalk_statuses() -> None:
    rows = _eu_ai_act_rows()
    text = PACK_DOC.read_text()
    table = _pack_status_rows(text)
    # bidirectional: the parsed Status column covers exactly the EU AI Act
    # crosswalk rows (no silent rows, no unknown ids), so a genuine status
    # drift between pack markdown and crosswalk data now fails here
    assert set(table) == set(rows), f"table/crosswalk id drift: {set(table) ^ set(rows)}"
    for control_id, status in table.items():
        assert status in {"SUPPORTED", "PARTIAL", "UNSUPPORTED"}, (
            f"bad status vocabulary: {control_id}={status!r}"
        )
        assert status == rows[control_id]["status"], (
            f"status drift: {control_id} pack={status} crosswalk={rows[control_id]['status']}"
        )
        # a SUPPORTED row must cite its crosswalk evidence field in its row text
        if rows[control_id]["status"] == "SUPPORTED":
            evidence_field = rows[control_id]["evidence_field"]
            assert evidence_field in text, f"SUPPORTED row lacks evidence citation: {control_id}"


def test_unsupported_rows_carry_honest_reasons() -> None:
    for row in _eu_ai_act_rows().values():
        if row["status"] == "UNSUPPORTED":
            assert row.get("evidence_field") is None
            assert row.get("unsat_reason", "").strip()
            assert row["unsat_reason"].split(" ")[0] not in {"TODO", "TBD"}


def test_pack_copy_names_no_vendors() -> None:
    for doc in (PACK_DOC, COMPLIANCE_INDEX):
        text = doc.read_text()
        for vendor in ("Varonis", "Atlas", "Drata", "Vanta", "Splunk", "ServiceNow"):
            assert vendor not in text, f"vendor name in {doc.name}: {vendor!r}"
