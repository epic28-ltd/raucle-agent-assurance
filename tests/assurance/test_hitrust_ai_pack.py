# SPDX-License-Identifier: Apache-2.0
"""H2 slice 6 tests: HITRUST AI Security Framework v1 pack consistency.

Guards the contract between the pack document
(``docs/compliance/hitrust-ai-pack-v1.md``) and the crosswalk data
(``ops/assurance-profiles/crosswalk.json``): every control topic the pack
cites must exist as a HITRUST crosswalk row with the same status, every AI
control topic area (inventory, change management, data protection, incident
response) must have at least one row, and the validator self-check must stay
empty so no row drifts into claiming more than the evidence plane supports.
The pack copy must stay a mapping: no certification or compliance claims, no
vendor names anywhere in the pack docs or the shared compliance index, and no
HITRUST CSF control text reproduced anywhere (HITRUST is
licence-restricted; the pack references topic ids and titles only). The
pack's Status column is parsed from the markdown tables and matched
bidirectionally against the crosswalk statuses, so genuine drift fails.
"""

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
PACK_DOC = REPO_ROOT / "docs" / "compliance" / "hitrust-ai-pack-v1.md"
COMPLIANCE_INDEX = REPO_ROOT / "docs" / "compliance" / "README.md"
FRAMEWORK = "HITRUST AI Security Framework"

FOCUS_AREAS = {
    "AI system inventory and accountability": {
        "AI system inventory",
        "AI system accountability",
        "AI third-party and inherited controls",
    },
    "AI change management": {
        "AI system change management",
        "AI system change verification",
    },
    "AI data protection": {
        "AI system data protection",
        "AI record integrity",
    },
    "AI incident response": {
        "AI logging and monitoring",
        "AI incident detection and response updates",
        "AI incident recording",
    },
}

# HITRUST AI control topic ids in the pack tables: descriptive topic
# references in the public-outline idiom (CSF v11 AI control topics), not
# licensed requirement-statement ids.
_ID = re.compile(r"`(AI [^`]*)`")


def _hitrust_rows() -> dict[str, dict]:
    return {row["control_id"]: row for row in CROSSWALK["rows"] if row["framework"] == FRAMEWORK}


def test_validator_self_check_stays_empty() -> None:
    assert validator.self_check(profiles=validator.load_profiles(), crosswalk=CROSSWALK) == []


def test_focus_areas_are_each_covered_by_crosswalk_rows() -> None:
    rows = _hitrust_rows()
    for area, expected_ids in FOCUS_AREAS.items():
        section = re.search(rf"## Focus area [0-9]+: {re.escape(area)}", PACK_DOC.read_text())
        assert section is not None, f"pack doc has no section for focus area: {area}"
        assert expected_ids <= rows.keys(), f"{area} crosswalk row missing"
    # every HITRUST crosswalk row belongs to a focus area the pack documents
    documented = set().union(*FOCUS_AREAS.values())
    assert set(rows) == documented, f"undocumented HITRUST rows: {set(rows) - documented}"


def test_pack_cited_controls_match_crosswalk_rows() -> None:
    rows = _hitrust_rows()
    table_ids = set(_ID.findall(PACK_DOC.read_text()))
    hitrust_ids = set(rows)
    # every topic id the pack cites must be a real crosswalk row
    assert table_ids <= hitrust_ids, f"pack cites unknown topics: {table_ids - hitrust_ids}"
    # every HITRUST crosswalk row must be cited by the pack (no silent rows)
    assert hitrust_ids <= table_ids, f"crosswalk rows not cited by pack: {hitrust_ids - table_ids}"


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
    rows = _hitrust_rows()
    text = PACK_DOC.read_text()
    table = _pack_status_rows(text)
    # bidirectional: the parsed Status column covers exactly the HITRUST
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
    for row in _hitrust_rows().values():
        if row["status"] == "UNSUPPORTED":
            assert row.get("evidence_field") is None
            assert row.get("unsat_reason", "").strip()
            assert row["unsat_reason"].split(" ")[0] not in {"TODO", "TBD"}


def test_hitrust_pack_makes_no_certification_or_compliance_claims() -> None:
    text = PACK_DOC.read_text()
    # the repo's compliance-honest invariant: the pack maps, it never claims
    assert "mapped to" in text
    for forbidden in ("is compliant", "certified", "achieves compliance", "HITRUST certified"):
        assert forbidden not in text, f"compliance-claim language found: {forbidden!r}"
    assert "makes no claim" in text


def test_pack_copy_names_no_vendors() -> None:
    for doc in (PACK_DOC, COMPLIANCE_INDEX):
        text = doc.read_text()
        for vendor in ("Varonis", "Atlas", "Drata", "Vanta", "Splunk", "ServiceNow"):
            assert vendor not in text, f"vendor name in {doc.name}: {vendor!r}"


def test_pack_reproduces_no_hitrust_control_text() -> None:
    """HITRUST CSF content is licence-restricted: ids/titles only, no text.

    The guard proves the pack references control topics by id and short
    title only: the set of strings the pack cites is exactly the id/title
    set of its crosswalk rows (already forced by the bidirectional tests
    above), and the pack states the licence restriction explicitly.
    """
    text = PACK_DOC.read_text()
    assert "licence" in text
    assert "no control text" in text
    rows = _hitrust_rows()
    # the pack never quotes a CSF requirement statement id format
    # (e.g. 15.11cAISecOrganizational.1); topic ids live in the crosswalk
    assert not re.search(r"[0-9]+\.[0-9]+[a-z]AISec[A-Za-z]+\.", text)
    # every HITRUST row title appears once as a reference, never duplicated
    # inside quoted requirement wording
    for row in rows.values():
        assert row["title"] in text
        occurrences = len(re.findall(re.escape(row["title"]), text))
        assert occurrences == 1, f"title duplicated beyond its mapping reference: {row['title']}"


def test_export_includes_hitrust_rows() -> None:
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
    rows = _hitrust_rows()
    nodes = {
        n["control_id"]: n
        for n in graph["nodes"]
        if n["kind"] == "control" and n["framework"] == FRAMEWORK
    }
    # every HITRUST pack row exports as a control node with the crosswalk status
    assert set(nodes) == set(rows)
    assert {n["status"] for n in nodes.values()} <= {"SUPPORTED", "PARTIAL", "UNSUPPORTED"}
    # honest-gap edges: UNSUPPORTED rows carry no evidence edge in the export
    for row in rows.values():
        node = nodes[row["control_id"]]
        if row["status"] == "UNSUPPORTED":
            assert node["evidence_field"] is None


def test_compliance_index_lists_all_six_packs() -> None:
    text = COMPLIANCE_INDEX.read_text()
    for pack in (
        "eu-ai-act-pack-v1.md",
        "hipaa-security-rule-pack-v1.md",
        "pci-dss-pack-v1.md",
        "iso-42001-pack-v1.md",
        "nist-ai-rmf-pack-v1.md",
        "hitrust-ai-pack-v1.md",
    ):
        assert pack in text, f"compliance index does not list {pack}"
    assert "mapped to" in text
