# SPDX-License-Identifier: Apache-2.0
"""Per-decision replay rendered from an audit pack (P1.1b slice).

The portal replay view (raucle-cloud) resolves the live chain of
record; this module renders the SAME replay for pack receipts, from
the audit pack alone: ``chain_graph.json`` (the P1.1a wire-up's
resolved authority graphs), ``receipts.jsonl`` (byte-exact envelopes)
and the pinned key snapshot. An auditor with no raucle access reads
the same story the compliance lead sees live.

Honesty rules, mirroring the portal view:

1. The decision summary, the policy binding state and the narrowed
   scope per hop come ONLY from the pack's resolved graph. A hop the
   pack cannot resolve is stated as unresolved, never inferred.
2. Proof: packs do not carry a z3/SMT proof artefact today. The
   documented honest state is ``no_proof_recorded`` for every subject;
   the replay TODO is to ship per-version proof artefacts into the
   pack (``policies/proof-*.json``) and render them here once they
   exist. A proof link that offline verification cannot follow is
   never rendered.
3. Verification: every envelope cited by the graph is checked against
   the pinned key snapshot with real Ed25519 verification; the state
   space (valid / invalid / unknown_key / unreachable) matches
   ADR-0001. Nothing is claimed through name coincidence.
4. The timestamp chain is the signed ``iat`` sequence plus the RFC
   3161 token presence the pack extracted, stated as recorded.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import pathlib
from typing import Any

_RECEIPTS_FILE = "receipts.jsonl"
_GRAPH_FILE = "chain_graph.json"


def replay_receipt_from_pack(pack_dir: pathlib.Path, receipt_hash: str) -> dict[str, Any]:
    """The replay of one decision, derived from the pack only.

    Raises LookupError when the pack holds no envelope (and no resolved
    graph) for ``receipt_hash``: a receipt the pack does not contain
    cannot be replayed, and replaying a pack receipt whose graph is the
    documented pending slot renders that honestly.
    """
    pack_dir = pathlib.Path(pack_dir)
    envelopes = _envelopes(pack_dir, receipt_hash)
    graph_doc = _graph_doc(pack_dir)
    graph = graph_doc.get("graphs", {}).get(receipt_hash)

    nodes = [n for n in (graph or {}).get("nodes", []) if n.get("kind") == "receipt"]
    by_id = {n["id"]: n for n in nodes}
    root = by_id.get(receipt_hash)
    policy_node = _policy_node(graph or {}, receipt_hash)
    hops = _hops(graph or {})

    return {
        "receipt_hash": receipt_hash,
        "source": f"audit pack {_RECEIPTS_FILE} + {_GRAPH_FILE}",
        "decision": _decision_summary(root, (envelopes[0] if envelopes else None)),
        "authority_chain": {
            "graph_status": graph_doc.get("status", "absent"),
            "nodes": nodes,
            "edges": (graph or {}).get("edges", []),
            "unknown": (graph or {}).get("unknown", []),
            "pruned": (graph or {}).get("pruned", []),
            "truncated": bool((graph or {}).get("truncated", False)),
        },
        "policy": _policy_section(policy_node, pack_dir),
        "hops": hops,
        "proofs": _proofs(policy_node),
        "verify": _verify(pack_dir, envelopes, by_id),
        "timestamps": _timestamps(graph or {}, envelopes),
    }


# -- inputs -------------------------------------------------------------------


def _envelopes(pack_dir: pathlib.Path, receipt_hash: str) -> list[str]:
    path = pack_dir / _RECEIPTS_FILE
    if not path.is_file():
        raise LookupError(receipt_hash)
    out: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.rstrip("\n")
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("receipt_hash") == receipt_hash:
            out.append(line.rstrip("\n"))
    if not out:
        raise LookupError(receipt_hash)
    return out


def _graph_doc(pack_dir: pathlib.Path) -> dict[str, Any]:
    path = pack_dir / _GRAPH_FILE
    if not path.is_file():
        return {"status": "absent"}
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError:
        return {"status": "unreadable"}
    return doc if isinstance(doc, dict) else {"status": "invalid"}


def _payload_of(envelope_line: str) -> dict[str, Any]:
    jws = json.loads(envelope_line)["jws"]
    seg = jws.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))


# -- sections -----------------------------------------------------------------


def _decision_summary(root: dict[str, Any] | None, envelope: str | None) -> dict[str, Any]:
    if root is None:
        # The graph never resolved this receipt: the replay states only
        # what the envelope itself proves.
        payload = _payload_of(envelope) if envelope else {}
        gate = payload.get("x_gate") if isinstance(payload.get("x_gate"), dict) else {}
        return {
            "state": "graph_absent",
            "decision": payload.get("guardrail_verdict") or gate.get("decision"),
            "tool": gate.get("tool"),
            "agent_id": gate.get("agent_id"),
            "iat": payload.get("iat"),
            "ruleset_hash": payload.get("ruleset_hash"),
        }
    gate = root.get("gate") or {}
    return {
        "state": "resolved",
        "decision": gate.get("decision") or root.get("guardrail_verdict"),
        "tool": gate.get("tool") or root.get("tool"),
        "agent_id": gate.get("agent_id") or root.get("agent_id"),
        "operation": root.get("operation"),
        "iat": root.get("iat"),
        "profile": root.get("profile"),
        "signature_state": root.get("signature"),
        "trace_id": gate.get("trace_id") or "",
    }


def _policy_node(graph: dict[str, Any], receipt_hash: str) -> dict[str, Any] | None:
    for edge in graph.get("edges", []):
        if edge.get("kind") == "policy_binding" and edge.get("from") == receipt_hash:
            for node in graph.get("nodes", []):
                if node.get("id") == edge.get("to") and node.get("kind") == "policy":
                    return node
    return None


def _policy_section(
    policy_node: dict[str, Any] | None, pack_dir: pathlib.Path
) -> dict[str, Any]:
    node = policy_node or {}
    section: dict[str, Any] = {
        "binding_state": node.get("binding_state", "unbound"),
        "policy_ref": node.get("policy_ref", ""),
        "rule_id": node.get("rule_id", ""),
        "ruleset_hash": node.get("ruleset_hash", ""),
        "deployed_versions": node.get("deployments", []),
        "version_in_force": None,
        "version_null_reason": (
            "a pack is a snapshot export: it carries no versioned policy"
            " store, so a decision-time version binding is available only"
            " where the graph's deployment events name one"
        ),
        "policy_files_in_pack": _policy_files(pack_dir),
    }
    for dep in section["deployed_versions"]:
        if dep.get("policy_id") and dep.get("version") is not None:
            section["version_in_force"] = {
                "policy_id": dep["policy_id"],
                "version": dep["version"],
                "matched_by": "deployment_event",
                "text_available": bool(section["policy_files_in_pack"]),
            }
            break
    return section


def _policy_files(pack_dir: pathlib.Path) -> list[str]:
    pol_dir = pack_dir / "policies"
    if not pol_dir.is_dir():
        return []
    return sorted(
        p.name for p in pol_dir.iterdir() if p.suffix in {".yaml", ".yml", ".json"}
    )


def _hops(graph: dict[str, Any]) -> list[dict[str, Any]]:
    parents: dict[str, str] = {}
    for edge in graph.get("edges", []):
        if edge.get("kind") == "delegation_parent":
            parents[edge["from"]] = edge["to"]
    delegation_nodes = {
        n["id"]: n for n in graph.get("nodes", []) if n.get("kind") == "delegation"
    }
    if not delegation_nodes:
        return [
            {
                "kind": "delegation",
                "state": "unresolved",
                "honest_note": "the pack carries no delegation ledger, so"
                " per-hop scope narrowing cannot be reconstructed offline"
                " unless the receipts' own graph resolves the hops",
            }
        ]
    ordered: list[str] = []
    seen: set[str] = set()
    for start in sorted(n for n in delegation_nodes if n not in parents.values()):
        current: str | None = start
        while current and current in delegation_nodes and current not in seen:
            ordered.append(current)
            seen.add(current)
            current = parents.get(current)
    ordered.extend(n for n in delegation_nodes if n not in seen)
    hops: list[dict[str, Any]] = []
    for node_id in ordered:
        node = dict(delegation_nodes[node_id])
        parent_id = parents.get(node_id)
        if parent_id and parent_id in delegation_nodes:
            node["narrowed_from_parent"] = _narrowed(
                delegation_nodes[parent_id].get("constraints") or {},
                node.get("constraints") or {},
            )
        node["proof"] = {
            "state": "no_proof_recorded",
            "detail": "no proof artefact ships in the audit pack; the"
            " receipted narrowing itself is the recorded evidence",
        }
        hops.append(node)
    return hops


def _narrowed(parent: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    added = {key: child[key] for key in sorted(set(child) - set(parent))}
    removed = sorted(set(parent) - set(child))
    changed = {
        key: {"from": parent[key], "to": child[key]}
        for key in sorted(set(parent) & set(child))
        if parent[key] != child[key]
    }
    return {"added": added, "removed": removed, "changed": changed}


def _proofs(policy_node: dict[str, Any] | None) -> list[dict[str, Any]]:
    node = policy_node or {}
    rule = node.get("rule_id", "")
    subject = "decision policy"
    if rule:
        subject = f"policy {node.get('policy_ref', '')} rule {rule}"
    return [
        {
            "subject": subject,
            "state": "no_proof_recorded",
            "detail": "the audit pack contains no z3/SMT proof artefact;"
            " replay TODO: ship per-version proofs as policies/proof-*.json"
            " at pack build time and render them here",
        }
    ]


# -- verification against the pinned snapshot ---------------------------------


def _verify(
    pack_dir: pathlib.Path, envelopes: list[str], by_id: dict[str, Any]
) -> list[dict[str, Any]]:
    keys = _key_snapshot(pack_dir)
    out: list[dict[str, Any]] = []
    for line in envelopes:
        rec = json.loads(line)
        state = _signature_state(rec, keys)
        out.append(
            {
                "receipt_hash": rec["receipt_hash"],
                "verify": state,
                "graph_signature_state": by_id.get(rec["receipt_hash"], {}).get(
                    "signature"
                ),
            }
        )
    return out


def _key_snapshot(pack_dir: pathlib.Path) -> dict[str, dict[str, Any]]:
    keys_dir = pack_dir / "keys"
    if not keys_dir.is_dir():
        return {}
    keys: dict[str, dict[str, Any]] = {}
    for key_file in sorted(keys_dir.iterdir()):
        for line in key_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except ValueError:
                continue
            kid = str(row.get("key_id", ""))
            if kid:
                keys[kid] = row
    return keys


def _signature_state(rec: dict[str, Any], keys: dict[str, dict[str, Any]]) -> str:
    """ADR-0001 state: valid | invalid | unknown_key | unreachable.

    Real Ed25519 verification against the pinned snapshot only; a
    missing prover is an unreachable state, never a silent pass.
    """
    try:
        header, payload_seg, sig = rec["jws"].split(".")
    except (KeyError, ValueError, AttributeError):
        return "invalid"
    try:
        kid = json.loads(_b64d(header)).get("kid")
        payload = json.loads(_b64d(payload_seg))
    except ValueError:
        return "invalid"
    # Integrity: the receipt hash re-derives from the receipt bytes.
    want = "sha256:" + hashlib.sha256(rec["jws"].encode()).hexdigest()
    if rec.get("receipt_hash") != want:
        return "invalid"
    root = keys.get(str(kid))
    if root is None:
        return "unknown_key"
    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
        from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (  # noqa: PLC0415
            Ed25519PublicKey,
        )
    except ImportError:
        return "unreachable"
    try:
        signing_input = (header + "." + payload_seg).encode("ascii")
        key = serialization.load_pem_public_key(
            root["public_key_pem"].encode("utf-8")
            if isinstance(root["public_key_pem"], str)
            else root["public_key_pem"]
        )
        if isinstance(key, Ed25519PublicKey):
            key.verify(_b64d(sig), signing_input)
        else:  # pragma: no cover - snapshot keys are Ed25519
            return "invalid"
    except (InvalidSignature, ValueError, TypeError):
        return "invalid"
    return "valid" if isinstance(payload, dict) else "invalid"


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _timestamps(graph: dict[str, Any], envelopes: list[str]) -> list[dict[str, Any]]:
    events: list[tuple[str, str, str, str]] = []  # (at, kind, id, anchoring)
    for line in envelopes:
        rec = json.loads(line)
        try:
            payload = _payload_of(line)
            at = dt.datetime.fromtimestamp(int(payload.get("iat", 0)), tz=dt.UTC)
        except (ValueError, TypeError, KeyError, OverflowError):
            continue
        anchoring = "rfc3161_token_in_pack" if isinstance(
            payload.get("x_timestamp"), dict
        ) and payload["x_timestamp"].get("token") else "signed_iat_only"
        events.append((at.isoformat(), "receipt", rec["receipt_hash"], anchoring))
    for node in graph.get("nodes", []):
        if node.get("kind") == "audit_event" and node.get("event_timestamp"):
            events.append(
                (str(node.get("event_timestamp")), "audit_event", node.get("id"), "recorded")
            )
    events.sort(key=lambda e: (e[0], e[2], e[1]))
    return [
        {"at": at, "kind": kind, "id": node_id, "anchoring": anchoring}
        for at, kind, node_id, anchoring in events
    ]
