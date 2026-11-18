# SPDX-License-Identifier: Apache-2.0
"""H2 slice 3 tests: PCI DSS compliance pack v1 consistency.

Guards the contract between the pack document
(`docs/compliance/pci-dss-pack-v1.md`) and the crosswalk data
(`ops/assurance-profiles/crosswalk.json`): every control id the pack cites
must exist as a PCI DSS crosswalk row with the same status, every focus
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
PACK_DOC = REPO_ROOT / "docs" / "compliance" / "pci-dss-pack-v1.md"
COMPLIANCE_INDEX = REPO_ROOT / "docs" / "compliance" / "README.md"

FOCUS_AREAS = {
    "logging (Requirement 10)": {
        "10.2 audit logging of access and events",
        "10.4 log review and anomaly response",
        "10.5 audit log retention",
    },
    "identity and authentication (Requirement 8)": {
        "8.2 user identification and accounts",
        "8.3/8.4 strong authentication and MFA",
    },
    "secure configurations (Requirement 2)": {"2.2 secure configurations"},
    "secure development and change control (Requirement 6)": {
        "6.2 secure software development",
        "6.5 change control",
    },
}


def _pci_dss_rows() -> dict[str, dict]:
    return {row["control_id"]: row for row in CROSSWALK["rows"] if row["framework"] == "PCI DSS"}


# PCI DSS control ids in the pack tables: numbered requirement references.
_ID = re.compile(r"`([0-9]+(?:\.[0-9])+[^`]*)`")


def test_validator_self_check_stays_empty() -> None:
    assert validator.self_check(profiles=validator.load_profiles(), crosswalk=CROSSWALK) == []


def test_focus_areas_are_each_covered_by_crosswalk_rows() -> None:
    rows = _pci_dss_rows()
    for area, expected_ids in FOCUS_AREAS.items():
        section = re.search(rf"## Focus area [0-9]+: {re.escape(area)}", PACK_DOC.read_text())
        assert section is not None, f"pack doc has no section for focus area: {area}"
        assert expected_ids <= rows.keys(), f"{area} crosswalk row missing"
    # every PCI DSS crosswalk row belongs to a focus area the pack documents
    documented = set().union(*FOCUS_AREAS.values())
    assert set(rows) == documented, f"undocumented PCI DSS rows: {set(rows) - documented}"


def test_pack_cited_controls_match_crosswalk_rows() -> None:
    rows = _pci_dss_rows()
    table_ids = set(_ID.findall(PACK_DOC.read_text()))
    pci_dss_ids = set(rows)
    # every id the pack cites must be a real crosswalk row
    assert table_ids <= pci_dss_ids, f"pack cites unknown controls: {table_ids - pci_dss_ids}"
    # every PCI DSS crosswalk row must be cited by the pack (no silent rows)
    assert pci_dss_ids <= table_ids, f"crosswalk rows not cited by pack: {pci_dss_ids - table_ids}"


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
    rows = _pci_dss_rows()
    text = PACK_DOC.read_text()
    table = _pack_status_rows(text)
    # bidirectional: the parsed Status column covers exactly the PCI DSS
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
    for row in _pci_dss_rows().values():
        if row["status"] == "UNSUPPORTED":
            assert row.get("evidence_field") is None
            assert row.get("unsat_reason", "").strip()
            assert row["unsat_reason"].split(" ")[0] not in {"TODO", "TBD"}


def test_pci_dss_pack_makes_no_cde_or_compliance_claims() -> None:
    text = PACK_DOC.read_text()
    # the repo's compliance-honest invariant: the pack maps, it never claims
    assert "mapped to" in text
    for forbidden in ("is compliant", "certified", "achieves compliance"):
        assert forbidden not in text, f"compliance-claim language found: {forbidden!r}"
    assert "cardholder data environment" in text
    assert "makes no claim" in text


def test_pack_copy_names_no_vendors() -> None:
    for doc in (PACK_DOC, COMPLIANCE_INDEX):
        text = doc.read_text()
        for vendor in ("Varonis", "Atlas", "Drata", "Vanta", "Splunk", "ServiceNow"):
            assert vendor not in text, f"vendor name in {doc.name}: {vendor!r}"
