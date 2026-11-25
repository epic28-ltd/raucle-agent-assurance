# SPDX-License-Identifier: Apache-2.0
"""SOC 2 TSC mapping v1 crosswalk, export and claim-boundary tests."""
from __future__ import annotations
import importlib.util, json, pathlib, re
REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location("oaa_assurance_profiles_validator", REPO_ROOT / "ops" / "assurance-profiles" / "validator.py")
assert _SPEC is not None
validator = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(validator)  # type: ignore[union-attr]
CROSSWALK = validator.load_crosswalk()
PACK_DOC = REPO_ROOT / "docs" / "compliance" / "soc2-pack-v1.md"
COMPLIANCE_INDEX = REPO_ROOT / "docs" / "compliance" / "README.md"
FRAMEWORK = "SOC 2"
def _rows() -> dict[str, dict]:
    return {r["control_id"]: r for r in CROSSWALK["rows"] if r["framework"] == FRAMEWORK}
def _table(text: str) -> dict[str, str]:
    out = {}
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not line.startswith("| Crosswalk control |"): continue
        assert "| Status |" in line and lines[i + 1].startswith("| ---")
        j = i + 2
        while j < len(lines) and lines[j].startswith("| `"):
            cells = [c.strip() for c in lines[j].strip().strip("|").split("|")]
            cid = cells[0].strip("`")
            assert cid not in out
            out[cid] = cells[2]
            j += 1
    return out
def test_validator_self_check_stays_empty():
    assert validator.self_check(profiles=validator.load_profiles(), crosswalk=CROSSWALK) == []
def test_full_criteria_inventory_is_present():
    expected = ({f"CC{n}.{i}" for n, count in [(1,5),(2,3),(3,4),(4,2),(5,3),(6,8),(7,5),(8,1),(9,2)] for i in range(1,count+1)} | {f"A1.{i}" for i in range(1,4)} | {f"C1.{i}" for i in range(1,3)} | {f"PI1.{i}" for i in range(1,6)} | {f"P1.{i}" for i in range(1,9)})
    ids = set(_rows())
    normalised = {re.match(r"^(CC[1-9]\\.[1-9])", x).group(1) if re.match(r"^(CC[1-9]\\.[1-9])", x) else x for x in ids}
    assert normalised == expected
def test_pack_table_matches_crosswalk_statuses_bidirectionally():
    rows = _rows(); table = _table(PACK_DOC.read_text())
    assert set(table) == set(rows)
    for cid, status in table.items():
        assert status in {"SUPPORTED","PARTIAL","UNSUPPORTED"} and status == rows[cid]["status"]
        if status == "SUPPORTED": assert rows[cid]["evidence_field"] in PACK_DOC.read_text()
def test_unsupported_rows_have_explicit_reasons():
    for row in _rows().values():
        if row["status"] == "UNSUPPORTED": assert row.get("evidence_field") is None and row.get("unsat_reason","").strip()
def test_existing_soc2_governance_profile_references_remain_valid():
    required = validator.load_profiles()["profiles"]["regulated"]["required_controls"]
    for cid in ("CC7.1 configuration monitoring","CC7.2 anomaly detection","CC9.1 access risk mitigation"):
        assert f"SOC 2:{cid}" in required and cid in _rows()
def test_export_contains_soc2_controls_and_honest_gaps():
    spec = importlib.util.spec_from_file_location("grc_export", REPO_ROOT / "tools" / "grc_export" / "export.py")
    assert spec is not None
    exporter = importlib.util.module_from_spec(spec); spec.loader.exec_module(exporter)  # type: ignore[union-attr]
    packet = json.loads((REPO_ROOT / "ops" / "assurance-profiles" / "fixtures" / "green.json").read_text())
    graph = exporter.build_graph(CROSSWALK, packet)
    nodes = {n["control_id"]: n for n in graph["nodes"] if n["kind"] == "control" and n["framework"] == FRAMEWORK}
    assert set(nodes) == set(_rows())
    for cid, row in _rows().items():
        if row["status"] == "UNSUPPORTED": assert nodes[cid]["evidence_field"] is None
def test_pack_avoids_attestation_and_compliance_claims():
    text = PACK_DOC.read_text().lower()
    assert "makes no claim" in text
    for phrase in ("is soc 2 compliant","soc 2 certified","has obtained a soc 2 report"): assert phrase not in text
def test_compliance_index_lists_soc2_pack():
    assert "soc2-pack-v1.md" in COMPLIANCE_INDEX.read_text()
