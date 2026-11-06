# SPDX-License-Identifier: Apache-2.0
"""GRC evidence-graph export (Sprint 13 / wave-6 lane D).

Emits a versioned, deterministic ``grc_evidence_graph/v1`` JSON document:
a machine-readable graph of every framework control's evidence status,
including the honest gaps, from two repo primitives only:

- the merged governance crosswalk (ops/assurance-profiles/crosswalk.json),
  which supplies every control node and its SUPPORTED / PARTIAL /
  UNSUPPORTED status, and
- an agent assurance packet (OV-1 shape or its fixture variant), which
  supplies the agents, policies, receipt hashes (hash only, bounded
  disclosure preserved) and the evidence fields the crosswalk cites.

Edges carry the honesty of the claim with them: ``evidence_satisfies_control``
only exists where the crosswalk names a packet evidence field (an
UNSUPPORTED control has no such edge - the gap is visible, never papered
over), and each such edge carries the crosswalk's status so a PARTIAL
control can never read as SUPPORTED. ``agent_bound_by_policy`` and
``receipt_part_of_chain'' edges are derived from the packet's own
declarations; a packet that declares none simply produces no edges.

NON-GOAL (documented): vendor integration. This tool emits generic,
versioned JSON only. It does not talk to any GRC product, and importing
its output into a specific vendor's API is out of scope by design for the
same reason the companion never duplicates the gate: the graph is the
portable, vendor-neutral boundary.

Determinism contract: the same inputs produce byte-identical JSON (sorted
keys, stable node/edge order, no wall-clock data). The ``graph`` digests
the canonical form of the body; ``graph_content_sha256'' is added after
the digest, outside it, in the OV-1 pattern.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

MODULE_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = MODULE_DIR.parent.parent
DEFAULT_CROSSWALK = REPO_ROOT / "ops" / "assurance-profiles" / "crosswalk.json"

GRAPH_KIND = "grc_evidence_graph"
GRAPH_SCHEMA_VERSION = 1

_CROSSWALK_STATUSES = ("SUPPORTED", "PARTIAL", "UNSUPPORTED")
_CANON_RECEIPT_HASH = re.compile(r"sha256:[0-9a-f]{64}")
_SLUG_RE = re.compile(r"[^a-z0-9]+")


class ExportError(ValueError):
    """Named, user-legible failure; nothing is silently dropped or repaired."""


def canonical_json(obj: object) -> str:
    """Deterministic canonical form: sorted keys, no whitespace padding."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _slug(value: str) -> str:
    return _SLUG_RE.sub("-", value.strip().lower()).strip("-")


def _load_json_file(path: pathlib.Path, label: str) -> object:
    if not path.is_file():
        raise ExportError(f"{label} not found: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ExportError(f"{label} unreadable ({path}): {exc}") from exc


def _dotted_lookup(packet: dict, dotted: str):
    """Follow a dotted path into the packet; None when absent.

    Path segments are matched literally, exactly like the OV-4 validator:
    a framework name with spaces ("EU AI Act") is one segment.
    """
    node: object = packet
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return None if node is None else node


def _str_list(value: object) -> list[str]:
    if isinstance(value, list):
        return sorted({str(v) for v in value})
    return []


# ---------------------------------------------------------------- packet ---


def _packet_agents(packet: dict) -> list[str]:
    # Canonical packet: agent_identity.agents; fixture variant: agent.id.
    agents = _str_list(_dotted_lookup(packet, "agent_identity.agents"))
    if not agents and isinstance(packet.get("agent"), dict):
        one = packet["agent"].get("id")
        if one:
            agents = [str(one)]
    return agents


def _packet_policies(packet: dict) -> list[str]:
    # Canonical packet: gate_coverage.distinct_policies; both shapes carry
    # the operator's policy_proof_refs. Sorted union, deduplicated.
    policies = set(_str_list(_dotted_lookup(packet, "gate_coverage.distinct_policies")))
    policies.update(_str_list(_dotted_lookup(packet, "policy_proof_refs")))
    return sorted(p for p in policies if p)


def _packet_receipts(packet: dict) -> list[str]:
    # Receipts by hash only; denial reasons never exist here to leak.
    receipts = _str_list(_dotted_lookup(packet, "receipt_chain.receipt_hashes"))
    for rh in receipts:
        if not _CANON_RECEIPT_HASH.fullmatch(rh):
            raise ExportError(f"packet receipt hash {rh!r} is not canonical sha256:<64 hex>")
    return receipts


# ----------------------------------------------------------------- nodes ---


def build_nodes(crosswalk: dict, packet: dict | None) -> list[dict]:
    """Every control row from the crosswalk, plus the packet's own entities.

    Control status comes from the crosswalk, straight: SUPPORTED, PARTIAL or
    UNSUPPORTED, never inferred from missing data. When the packet also
    declares a governance status for the same control, it is recorded beside
    the crosswalk status, and a packet claiming more than the crosswalk
    supports is flagged (status_conflict) rather than reconciled away.
    """
    nodes: list[dict] = []

    agents = _packet_agents(packet) if packet else []
    for agent in agents:
        nodes.append({"kind": "agent", "id": f"agent:{agent}", "name": agent})

    for policy in _packet_policies(packet) if packet else []:
        nodes.append({"kind": "policy", "id": f"policy:{policy}", "ref": policy})

    for rh in _packet_receipts(packet) if packet else []:
        nodes.append({"kind": "receipt", "id": f"receipt:{rh}", "hash": rh})

    rows = crosswalk.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ExportError("crosswalk has no rows")
    for row in rows:
        status = row.get("status")
        if status not in _CROSSWALK_STATUSES:
            raise ExportError(f"crosswalk row {row!r} status is not one of {_CROSSWALK_STATUSES}")
        framework = row.get("framework")
        control_id = row.get("control_id")
        if not framework or not control_id:
            raise ExportError(f"crosswalk row lacks framework/control_id: {row!r}")
        nid = f"control:{_slug(str(framework))}:{_slug(str(control_id))}"
        node = {
            "kind": "control",
            "id": nid,
            "framework": str(framework),
            "control_id": str(control_id),
            "title": row.get("title"),
            "status": status,
            "evidence_field": row.get("evidence_field"),
        }
        if row.get("unsat_reason"):
            node["unsat_reason"] = row["unsat_reason"]
        if row.get("basis"):
            node["basis"] = row["basis"]
        if packet is not None:
            declared = _declared_status(packet, str(framework), str(control_id))
            if declared is not None:
                node["declared_status"] = declared
                node["status_conflict"] = declared != status
        nodes.append(node)

    # Evidence nodes: one per distinct crosswalk evidence field that the
    # packet actually carries. A SUPPORTED field the packet lacks is a
    # named (empty) absence: the edge for it is dropped, with a reason.
    fields = sorted(
        {
            str(r["evidence_field"])
            for r in rows
            if r.get("evidence_field") and r.get("status") != "UNSUPPORTED"
        }
    )
    for field in fields:
        if packet is None:
            continue
        value = _dotted_lookup(packet, field)
        if value is None:
            continue
        node: dict = {"kind": "evidence", "id": f"evidence:{field}", "packet_field": field}
        if isinstance(value, list):
            node["value_kind"] = "list"
            node["value_count"] = len(value)
            node["value"] = sorted(str(v) for v in value)
        elif isinstance(value, int) and not isinstance(value, bool):
            node["value_kind"] = "number"
            node["value"] = value
        elif isinstance(value, dict):
            node["value_kind"] = "object"
            node["value_digest"] = (
                "sha256:" + hashlib.sha256(canonical_json(value).encode()).hexdigest()
            )
        else:
            node["value_kind"] = "string"
            node["value"] = str(value)
        nodes.append(node)

    return sorted(nodes, key=lambda n: (n["kind"], n["id"]))


def _declared_status(packet: dict, framework: str, control_id: str) -> str | None:
    gov = _dotted_lookup(packet, "governance_mapping") or _dotted_lookup(packet, "governance")
    if not isinstance(gov, dict):
        return None
    controls = gov.get(framework)
    if not isinstance(controls, dict):
        return None
    entry = controls.get(control_id)
    if isinstance(entry, dict):
        entry = entry.get("status")
    return entry if isinstance(entry, str) else None


# ----------------------------------------------------------------- edges ---


def build_edges(crosswalk: dict, packet: dict | None, nodes: list[dict]) -> list[dict]:
    """Edges, each honest: status rides on the edge, gaps stay gaps."""
    node_ids = {n["id"] for n in nodes}
    edges: list[dict] = []

    agents = [n["name"] for n in nodes if n["kind"] == "agent"]
    policies = [n["ref"] for n in nodes if n["kind"] == "policy"]
    for agent in agents:
        for policy in policies:
            edges.append(
                {
                    "kind": "agent_bound_by_policy",
                    "source": f"agent:{agent}",
                    "target": f"policy:{policy}",
                }
            )

    # A receipt belongs to the chain of every agent the packet names; a
    # packet that names no agent gets no chain edges (honest emptiness).
    receipts = [n["hash"] for n in nodes if n["kind"] == "receipt"]
    for agent in agents:
        for rh in receipts:
            edges.append(
                {
                    "kind": "receipt_part_of_chain",
                    "source": f"receipt:{rh}",
                    "target": f"agent:{agent}",
                }
            )

    # evidence satisfies control - only where the crosswalk names a packet
    # field. An UNSUPPORTED control gets no edge at all: the honest gap.
    evidence_ids = {n["packet_field"]: n["id"] for n in nodes if n["kind"] == "evidence"}
    for row in crosswalk["rows"]:
        if row.get("status") == "UNSUPPORTED":
            continue
        field = row.get("evidence_field")
        if not field:
            continue
        eid = evidence_ids.get(str(field))
        if eid is None:
            continue  # field absent from the packet: no edge, not a fake one
        nid = f"control:{_slug(str(row['framework']))}:{_slug(str(row['control_id']))}"
        edges.append(
            {
                "kind": "evidence_satisfies_control",
                "source": eid,
                "target": nid,
                "status": row["status"],
            }
        )

    edges = [e for e in edges if e["source"] in node_ids and e["target"] in node_ids]
    return sorted(edges, key=lambda e: (e["kind"], e["source"], e["target"]))


# ----------------------------------------------------------------- build ---


def build_graph(crosswalk: dict, packet: dict | None) -> dict:
    graph = {
        "kind": GRAPH_KIND,
        "schema_version": GRAPH_SCHEMA_VERSION,
        "guard": (
            "This graph maps framework controls to the evidence the agent"
            " assurance packet actually carries, honestly, including gaps."
            " Statuses come from the governance crosswalk; UNSUPPORTED means"
            " nothing in the evidence plane satisfies the control today. It"
            " asserts no certification, no approval, no attestation, and no"
            " warranty of any kind."
        ),
        "inputs": {
            "crosswalk_version": crosswalk.get("version"),
            "packet_sha256": (
                "sha256:" + hashlib.sha256(canonical_json(packet).encode()).hexdigest()
                if packet
                else None
            ),
            "node_count": None,
            "edge_count": None,
        },
    }
    nodes = build_nodes(crosswalk, packet)
    edges = build_edges(crosswalk, packet, nodes)
    graph["nodes"] = nodes
    graph["edges"] = edges
    graph["inputs"]["node_count"] = len(nodes)
    graph["inputs"]["edge_count"] = len(edges)
    graph["graph_content_sha256"] = (
        "sha256:" + hashlib.sha256(canonical_json(graph).encode()).hexdigest()
    )
    return graph


def render(graph: dict) -> str:
    return json.dumps(graph, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export the GRC evidence graph (v1).")
    parser.add_argument("--crosswalk", type=pathlib.Path, default=DEFAULT_CROSSWALK)
    parser.add_argument("--packet", type=pathlib.Path, default=None)
    parser.add_argument("--out", type=pathlib.Path, default=None, help="default: stdout")
    args = parser.parse_args(argv)

    try:
        crosswalk = _load_json_file(args.crosswalk, "crosswalk")
        if not isinstance(crosswalk, dict):
            raise ExportError("crosswalk must be a JSON object")
        packet = None
        if args.packet is not None:
            packet = _load_json_file(args.packet, "packet")
            if not isinstance(packet, dict):
                raise ExportError("packet must be a JSON object")
        graph = build_graph(crosswalk, packet)
        text = render(graph)
        if args.out is not None:
            args.out.write_text(text, encoding="utf-8")
            print(
                f"wrote {args.out}: {graph['inputs']['node_count']} nodes,"
                f" {graph['inputs']['edge_count']} edges"
            )
        else:
            sys.stdout.write(text)
    except ExportError as exc:
        print(f"grc-export: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
