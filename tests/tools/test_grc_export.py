# SPDX-License-Identifier: Apache-2.0
"""GRC evidence-graph export tests: determinism, crosswalk coverage,
schema validation and honest UNSUPPORTED edges."""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

jsonschema = pytest.importorskip("jsonschema")

REPO = pathlib.Path(__file__).resolve().parents[2]
CROSSWALK = REPO / "ops" / "assurance-profiles" / "crosswalk.json"
SCHEMA = REPO / "schemas" / "grc_evidence_graph.schema.json"
FIXTURES = REPO / "ops" / "assurance-profiles" / "fixtures"
GREEN = FIXTURES / "green.json"

RH1 = "sha256:" + "a" * 64
RH2 = "sha256:" + "b" * 64


def _load_exporter():
    spec = importlib.util.spec_from_file_location(
        "grc_export", REPO / "tools" / "grc_export" / "export.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _build(packet):
    exporter = _load_exporter()
    crosswalk = json.loads(CROSSWALK.read_text())
    return exporter, exporter.build_graph(crosswalk, packet)


def _green_with_receipts():
    packet = json.loads(GREEN.read_text())
    packet["receipt_chain"]["receipt_hashes"] = [RH2, RH1]  # unsorted on purpose
    return packet


# ------------------------------------------------------- crosswalk coverage


def test_every_crosswalk_row_is_a_control_node_with_its_crosswalk_status():
    _, graph = _build(_green_with_receipts())
    crosswalk = json.loads(CROSSWALK.read_text())
    controls = [n for n in graph["nodes"] if n["kind"] == "control"]
    assert len(controls) == len(crosswalk["rows"])  # every row is a control node
    assert len(controls) >= 28  # incl. the 8 N7 AIUC-1 rows
    by_id = {(n["framework"], n["control_id"]): n for n in controls}
    for row in crosswalk["rows"]:
        node = by_id[(row["framework"], row["control_id"])]
        assert node["status"] == row["status"]
        assert node["evidence_field"] == row["evidence_field"]
    statuses = {n["status"] for n in controls}
    assert statuses == {"SUPPORTED", "PARTIAL", "UNSUPPORTED"}


def test_control_node_carries_unsat_reason_for_the_honest_gap():
    _, graph = _build(None)
    control = next(
        n
        for n in graph["nodes"]
        if n["kind"] == "control"
        and n["status"] == "UNSUPPORTED"
        and n["control_id"] == "Art 11 incident reporting"
    )
    assert control["evidence_field"] is None
    assert control["unsat_reason"]


# ------------------------------------------------------ schema + edges


def test_output_validates_against_the_graph_schema():
    exporter, graph = _build(_green_with_receipts())
    jsonschema.validate(graph, json.loads(SCHEMA.read_text()))
    # And the CLI render is the same document shape.
    assert json.loads(exporter.render(graph)) == graph


def test_satisfies_edges_only_exist_where_the_crosswalk_names_a_field():
    _, graph = _build(_green_with_receipts())
    sat = [e for e in graph["edges"] if e["kind"] == "evidence_satisfies_control"]
    controls = {
        f"{n['framework']}:{n['control_id']}": n for n in graph["nodes"] if n["kind"] == "control"
    }
    sat_targets = {e["target"] for e in sat}
    exporter = _load_exporter()
    packet = _green_with_receipts()
    for _key, node in controls.items():
        field = node["evidence_field"]
        present = (
            node["status"] != "UNSUPPORTED"
            and field is not None
            and exporter._dotted_lookup(packet, field) is not None
        )
        if present:
            assert node["id"] in sat_targets
        else:
            assert node["id"] not in sat_targets  # no edge for the honest gap
    for edge in sat:
        assert edge["status"] in ("SUPPORTED", "PARTIAL")  # status rides the edge


def test_no_satisfies_edge_for_an_evidence_field_the_packet_lacks():
    packet = _green_with_receipts()
    packet.pop("risk_annotations")  # crosswalk SUPPORT rows cite this field
    _, graph = _build(packet)
    evidence = next(e for e in graph["edges"] if e["kind"] == "evidence_satisfies_control")
    src_fields = [
        n["packet_field"]
        for n in graph["nodes"]
        if n["kind"] == "evidence" and n["id"] == evidence["source"]
    ]
    assert "risk_annotations" not in src_fields


def test_agent_policy_and_receipt_chain_edges():
    packet = _green_with_receipts()
    _, graph = _build(packet)
    bound = [e for e in graph["edges"] if e["kind"] == "agent_bound_by_policy"]
    assert {(e["source"], e["target"]) for e in bound} == {
        ("agent:fixture-green", "policy:policy://fixture/shell")
    }
    chain = [e for e in graph["edges"] if e["kind"] == "receipt_part_of_chain"]
    assert {(e["source"], e["target"]) for e in chain} == {
        (f"receipt:{rh}", "agent:fixture-green") for rh in (RH1, RH2)
    }
    # Receipts carry the hash only, sorted for determinism.
    receipts = sorted(n["hash"] for n in graph["nodes"] if n["kind"] == "receipt")
    assert receipts == [RH1, RH2]
    assert not any(n["kind"] == "receipt" and "jws" in n for n in graph["nodes"])


def test_packet_status_conflict_is_flagged_not_reconciled():
    packet = _green_with_receipts()
    packet["governance"]["DORA"]["Art 11 incident reporting"] = {"status": "SUPPORTED"}
    _, graph = _build(packet)
    control = next(
        n
        for n in graph["nodes"]
        if n["kind"] == "control"
        and (n["framework"], n["control_id"]) == ("DORA", "Art 11 incident reporting")
    )
    assert control["status"] == "UNSUPPORTED"  # crosswalk stays authoritative
    assert control["declared_status"] == "SUPPORTED"
    assert control["status_conflict"] is True


# ----------------------------------------------------------- determinism


def test_same_inputs_produce_byte_identical_output(tmp_path, monkeypatch):
    monkeypatch.chdir(REPO)
    exporter = _load_exporter()
    packet = _green_with_receipts()
    out1, out2 = tmp_path / "g1.json", tmp_path / "g2.json"
    crosswalk = str(CROSSWALK)
    rc1 = exporter.main(
        ["--crosswalk", crosswalk, "--packet", str(_write(packet, tmp_path)), "--out", str(out1)]
    )
    rc2 = exporter.main(
        ["--crosswalk", crosswalk, "--packet", str(_write(packet, tmp_path)), "--out", str(out2)]
    )
    assert (rc1, rc2) == (0, 0)
    assert out1.read_text() == out2.read_text()
    graph = json.loads(out1.read_text())
    counts = graph["inputs"]
    assert counts["node_count"] == len(graph["nodes"])
    assert counts["edge_count"] == len(graph["edges"])


def _write(packet, tmp_path):
    p = tmp_path / "packet.json"
    p.write_text(json.dumps(packet))
    return p


def test_cli_writes_and_names_counts(tmp_path, capsys):
    exporter = _load_exporter()
    out = tmp_path / "graph.json"
    rc = exporter.main(
        ["--packet", str(_write(_green_with_receipts(), tmp_path)), "--out", str(out)]
    )
    assert rc == 0
    text = capsys.readouterr().out
    assert "nodes" in text and "edges" in text
    graph = json.loads(out.read_text())
    assert graph["kind"] == "grc_evidence_graph"
    assert graph["schema_version"] == 1


def test_non_canonical_receipt_hash_is_a_named_failure():
    exporter = _load_exporter()
    packet = _green_with_receipts()
    packet["receipt_chain"]["receipt_hashes"] = ["sha256:deadbeef"]
    with pytest.raises(exporter.ExportError, match="not canonical sha256"):
        exporter.build_graph(json.loads(CROSSWALK.read_text()), packet)


def test_crosswalk_row_with_bad_status_is_a_named_failure():
    exporter = _load_exporter()
    bad = {
        "version": 1,
        "rows": [
            {"framework": "F", "control_id": "C", "evidence_field": None, "status": "COVERED"}
        ],
    }
    with pytest.raises(exporter.ExportError, match="status is not one of"):
        exporter.build_graph(bad, None)
