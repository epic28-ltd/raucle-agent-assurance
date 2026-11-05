# SPDX-License-Identifier: Apache-2.0
"""Agent Assurance Packet (OV-1).

Versioned, deterministic packet compiled from a receipt-chain evidence
store (canonical ``{receipt_hash, jws}`` JSONL lines) plus optional
operator-supplied references: capability and policy-proof refs, governance
crosswalk ids (OV-4 supplies these; empty is honest and accepted), and
risk annotations.

Determinism contract: the same inputs produce byte-identical packet JSON
(stable field order, no wall-clock data of any kind) and a stable
``packet_sha256`` over the canonical form of the packet body.

Fail-visible contract: a tampered, malformed or missing input is an error
that names its cause; nothing is silently dropped or repaired. Receipt
integrity is checked the way the standalone pack verifier checks it: the
recorded ``receipt_hash`` must re-derive from the JWS line itself.

Bounded disclosure: packet and HTML summary carry ids, digests and counts
only. Receipt denial reasons (which may quote constraint values) never
enter the packet; the tests pin this.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import pathlib
import re
from typing import cast

PACKET_SCHEMA_VERSION = 1

# Governance mapping slots (OV-4 crosswalk ids land here; empty is honest).
GOVERNANCE_SLOTS = (
    "dora",
    "eu_ai_act",
    "iso_42001",
    "soc_2",
    "nist_ai_rmf",
    "owasp_llm",
)

_DECISION_LABELS = {
    "allow": "admitted",
    "deny": "refused",
    "hold": "held",
    "held": "held",
}

_CANON_RECEIPT_HASH = re.compile(r"sha256:[0-9a-f]{64}")

# The mandatory honesty guard, in the GOV-01 pattern: the packet records
# observation, not compliance. Both the packet JSON and the HTML summary
# carry it; the tests pin its presence.
GUARD_SENTENCE = (
    "This packet records what was cryptographically observed inside a"
    " deliberately narrow scope. It does not establish legal or regulatory"
    " compliance, and it asserts no certification, no approval, no"
    " accreditation, no attestation, and no warranty of any kind."
)

PACKET_KIND = "agent_assurance_packet"


def canonical_json(obj: object) -> str:
    """Deterministic canonical form: sorted keys, no whitespace padding."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# ------------------------------------------------------------ load/store ---


def _validated_line(raw: str, label: str) -> tuple[str, dict]:
    """(stripped line, gate payload) or fail-visible ValueError.

    Tamper check mirrors the standalone pack verifier: the recorded
    ``receipt_hash`` must re-derive from the JWS bytes as shipped.
    """
    line = raw.rstrip("\n")
    if not line:
        raise ValueError(f"{label}: blank store line")
    try:
        rec = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label}: not a JSON object line ({exc})") from exc
    if not isinstance(rec, dict):
        raise ValueError(f"{label}: store line is {type(rec).__name__}, not an object")
    jws = rec.get("jws")
    rh = rec.get("receipt_hash")
    if not isinstance(rh, str) or not _CANON_RECEIPT_HASH.fullmatch(rh.strip().lower()):
        raise ValueError(f"{label}: receipt_hash {rh!r} is not canonical sha256:<64 hex>")
    if not isinstance(jws, str) or jws.count(".") != 2:
        raise ValueError(f"{label}: jws envelope is missing or not a compact JWS")
    want = "sha256:" + hashlib.sha256(jws.encode()).hexdigest()
    if rh.strip().lower() != want:
        raise ValueError(
            f"{label}: receipt_hash does not re-derive from the receipt bytes (tampered)"
        )
    try:
        payload_b64 = jws.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4)))
    except Exception as exc:
        raise ValueError(f"{label}: unreadable envelope payload ({exc})") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"{label}: envelope payload is not a JSON object")
    return line, payload


def read_store(store_path: pathlib.Path) -> list[tuple[str, dict]]:
    """Every store line, validated. Missing or malformed store: named error.

    No line is silently skipped: this packet is a coverage claim, so a
    line that cannot be understood must stop the build.
    """
    if not store_path.is_file():
        raise ValueError(f"evidence store not found: {store_path}")
    out: list[tuple[str, dict]] = []
    for i, raw in enumerate(store_path.read_text(encoding="utf-8").splitlines(), start=1):
        if not raw.strip():
            continue
        out.append(_validated_line(raw, f"{store_path.name} line {i}"))
    if not out:
        raise ValueError(f"evidence store {store_path} has no receipt lines")
    return out


# ---------------------------------------------------------------- inputs ---


def _load_named_json(path: pathlib.Path | None, label: str) -> object:
    """Operator-supplied JSON reference file, or None when not given."""
    if path is None:
        return None
    if not path.is_file():
        raise ValueError(f"{label} file not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _sorted_str_list(value: object, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{label} must be a list of strings")
    return sorted(set(value))


# ---------------------------------------------------------------- compile ---


def _gate(payload: dict) -> dict | None:
    gate = payload.get("x_gate")
    return gate if isinstance(gate, dict) else None


def _decision(payload: dict) -> str | None:
    """Gate decision, reading x_gate first (gate receipts bind it there)."""
    gate = _gate(payload)
    if gate is not None and gate.get("decision"):
        return str(gate["decision"])
    verdict = payload.get("guardrail_verdict")
    return str(verdict) if verdict else None


def build_packet(
    evidence_store: pathlib.Path,
    *,
    capability_refs: list[str] | None = None,
    policy_proof_refs: list[str] | None = None,
    governance_mapping: dict[str, list[str]] | None = None,
    risk_annotations: list[str] | None = None,
) -> dict:
    """Compile the versioned packet. Deterministic; fail-visible on bad input."""
    if not evidence_store.is_file():
        raise ValueError(f"evidence store not found: {evidence_store}")
    store_file_sha = "sha256:" + hashlib.sha256(evidence_store.read_bytes()).hexdigest()
    lines = read_store(evidence_store)

    agents: set[str] = set()
    issuers: set[str] = set()
    operations: dict[str, int] = {}
    policies: set[str] = set()
    rule_ids: set[str] = set()
    ruleset_hashes: set[str] = set()
    receipt_hashes: list[str] = []
    counts = {"admitted": 0, "held": 0, "refused": 0, "other": 0, "without_gate": 0}
    event_times: list[int] = []

    for line, payload in lines:
        receipt_hashes.append(json.loads(line)["receipt_hash"])
        agents.add(str(payload.get("agent_id", "")))
        issuers.add(str(payload.get("iss", "")))
        if "iat" in payload:
            with contextlib.suppress(TypeError, ValueError):
                event_times.append(int(payload["iat"]))
        op = payload.get("operation")
        operations[str(op)] = operations.get(str(op), 0) + 1
        rsh = payload.get("ruleset_hash")
        if isinstance(rsh, str) and rsh:
            ruleset_hashes.add(rsh)
        decision = _decision(payload)
        if _gate(payload) is None:
            counts["without_gate"] += 1
            continue
        policies.add(str(_gate(payload).get("policy", "")))  # type: ignore[union-attr]
        rid = _gate(payload).get("rule_id", "")  # type: ignore[union-attr]
        if rid:
            rule_ids.add(str(rid))
        label = _DECISION_LABELS.get(decision or "", "other")
        counts[label] = counts.get(label, 0) + 1

    if governance_mapping is None:
        gov = {slot: [] for slot in GOVERNANCE_SLOTS}
    else:
        gov = {slot: [] for slot in GOVERNANCE_SLOTS}
        for name, ids in sorted(governance_mapping.items()):
            if name in GOVERNANCE_SLOTS:
                gov[name] = _sorted_str_list(ids, f"governance/{name}")
            else:
                # An unknown framework name is kept honestly, never discarded.
                gov[name] = _sorted_str_list(ids, f"governance/{name}")

    packet = {
        "kind": PACKET_KIND,
        "schema_version": PACKET_SCHEMA_VERSION,
        "guard": GUARD_SENTENCE,
        "inputs": {"evidence_store_sha256": store_file_sha},
        "packet_content_sha256": "",
        "agent_identity": {
            "agents": sorted(a for a in agents if a),
            "issuers": sorted(i2 for i2 in issuers if i2),
        },
        "receipt_chain": {
            "line_count": len(lines),
            "receipt_hashes": sorted(receipt_hashes),
            "operations": dict(sorted(operations.items())),
            "ruleset_hashes": sorted(ruleset_hashes),
            "first_event_time": min(event_times) if event_times else None,
            "last_event_time": max(event_times) if event_times else None,
        },
        "gate_coverage": {
            "admitted": counts["admitted"],
            "held": counts["held"],
            "refused": counts["refused"],
            "other": counts["other"],
            "without_gate": counts["without_gate"],
            "distinct_policies": sorted(p for p in policies if p),
            "distinct_rule_ids": sorted(rule_ids),
        },
        "capability_refs": sorted(set(capability_refs or [])),
        "policy_proof_refs": sorted(set(policy_proof_refs or [])),
        "governance_mapping": gov,
        "risk_annotations": sorted(set(risk_annotations or [])),
    }
    body = dict(packet)
    body.pop("packet_content_sha256", None)
    packet["packet_content_sha256"] = (
        "sha256:" + hashlib.sha256(canonical_json(body).encode()).hexdigest()
    )
    return packet


# ------------------------------------------------------------------ html ---


def html_summary(packet: dict) -> str:
    """textContent-only HTML summary. No scripting, no inline handlers."""
    e = lambda s: (  # noqa: E731 - tiny local escaping helper
        str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    )
    lines = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>Agent Assurance Packet (schema v{packet['schema_version']})</title>",
        "</head>",
        "<body>",
        "<h1>Agent Assurance Packet</h1>",
        "<p>Schema version: " + e(packet["schema_version"]) + "</p>",
        "<p>" + e(packet["guard"]) + "</p>",
        "<h2>Agent identity</h2>",
        "<p>Agents: " + e(", ".join(packet["agent_identity"]["agents"]) or "none") + "</p>",
        "<p>Issuers: " + e(", ".join(packet["agent_identity"]["issuers"]) or "none") + "</p>",
        "<h2>Receipt chain</h2>",
        "<p>Line count: " + e(packet["receipt_chain"]["line_count"]) + "</p>",
        "<p>Receipt hashes:</p><ul>",
        *[f"<li>{e(h)}</li>" for h in packet["receipt_chain"]["receipt_hashes"]],
        "</ul>",
        "<h2>Gate coverage</h2>",
        "<ul>",
        *[f"<li>{e(k)}: {e(v)}</li>" for k, v in packet["gate_coverage"].items()],
        "</ul>",
        "<h2>Capability refs</h2>",
        "<p>" + e(", ".join(packet["capability_refs"]) or "none declared") + "</p>",
        "<h2>Policy-proof refs</h2>",
        "<p>" + e(", ".join(packet["policy_proof_refs"]) or "none declared") + "</p>",
        "<h2>Governance mapping</h2>",
        "<ul>",
        *[
            f"<li>{e(k)}: {e(', '.join(v) or 'unsupported (no crosswalk ids supplied)')}</li>"
            for k, v in packet["governance_mapping"].items()
        ],
        "</ul>",
        "<h2>Risk annotations</h2>",
        "<ul>",
        *[f"<li>{e(r)}</li>" for r in packet["risk_annotations"]],
        "</ul>",
        "<h2>Integrity</h2>",
        "<p>Packet content sha256: " + e(packet["packet_content_sha256"]) + "</p>",
        "<p>Inputs: " + e(canonical_json(packet["inputs"])) + "</p>",
        "</body>",
        "</html>",
    ]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------- cli ---


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="OV-1: build a deterministic agent assurance packet")
    ap.add_argument("--evidence-store", required=True)
    ap.add_argument("--capability-refs", help="JSON list file of capability refs")
    ap.add_argument("--policy-proof-refs", help="JSON list file of policy-proof refs")
    ap.add_argument("--governance", help="JSON object file: framework -> crosswalk ids")
    ap.add_argument("--risk-annotations", help="JSON list file of risk annotation strings")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    try:
        packet = build_packet(
            pathlib.Path(args.evidence_store).expanduser().resolve(),
            capability_refs=_sorted_str_list(
                _load_named_json(
                    pathlib.Path(args.capability_refs).expanduser().resolve(), "capability-refs"
                )
                if args.capability_refs
                else None,
                "capability-refs",
            )
            if args.capability_refs
            else None,
            policy_proof_refs=_sorted_str_list(
                _load_named_json(
                    pathlib.Path(args.policy_proof_refs).expanduser().resolve(),
                    "policy-proof-refs",
                )
                if args.policy_proof_refs
                else None,
                "policy-proof-refs",
            )
            if args.policy_proof_refs
            else None,
            governance_mapping=cast(
                "dict[str, list[str]] | None",
                _load_named_json(pathlib.Path(args.governance).expanduser().resolve(), "governance")
                if args.governance
                else None,
            ),
            risk_annotations=_sorted_str_list(
                _load_named_json(
                    pathlib.Path(args.risk_annotations).expanduser().resolve(),
                    "risk-annotations",
                )
                if args.risk_annotations
                else None,
                "risk-annotations",
            )
            if args.risk_annotations
            else None,
        )
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"rauckle-assurance-packet: FAIL: {exc}", flush=True)
        return 1
    out_dir = pathlib.Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    text = json.dumps(packet, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    json_path = out_dir / "agent_assurance_packet.json"
    html_path = out_dir / "agent_assurance_packet.html"
    with open(json_path, "w", encoding="utf-8") as fh:
        fh.write(text)
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write(html_summary(packet))
    print(
        canonical_json(
            {
                "packet_json": str(json_path),
                "packet_html": str(html_path),
                "packet_content_sha256": packet["packet_content_sha256"],
                "receipt_line_count": packet["receipt_chain"]["line_count"],
            }
        )
    )
    return 0
