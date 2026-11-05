# SPDX-License-Identifier: Apache-2.0
"""Agent Assurance Packet (OV-1).

Versioned, deterministic packet compiled from a receipt-chain evidence
store (canonical ``{receipt_hash, jws}`` JSONL lines) plus optional
operator-supplied references: capability and policy-proof refs, governance
crosswalk ids (OV-4 supplies these; empty is honest and accepted), and
risk annotations.

Determinism contract: the same inputs produce byte-identical packet JSON
(stable field order, no wall-clock data of any kind) and a stable
``packet_sha256`` over the canonical form of the packet body. An optional
ML-DSA-65 signature of the packet digest (``packet_pq_signature``, OV-22)
is added after the digest, sits outside the digest body, and is equally
deterministic for the same key.

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

try:  # OV-22: raucle ships the ML-DSA-65 primitive; PQ signing fails visibly without it
    import raucle.pq as _rqpq
except ModuleNotFoundError:  # pragma: no cover - dependency-dependent
    _rqpq = None

SHA256_PREFIX = "sha256:"
PACKET_SCHEMA_VERSION = 1

_CLOSE_UL = "</ul>"
_EMPTY = "none"
_EMPTY_DECLARED = "none declared"
_UNSUPPORTED = "unsupported (no crosswalk ids supplied)"

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
    want = SHA256_PREFIX + hashlib.sha256(jws.encode()).hexdigest()
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


# ------------------------------------------------------------ summaries ---


def _store_summary(lines: list[tuple[str, dict]]) -> dict:
    """Aggregate counts and identity sets over validated store lines."""
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
        gate = _gate(payload)
        if gate is None:
            counts["without_gate"] += 1
            continue
        pol = gate.get("policy", "")
        if pol:
            policies.add(str(pol))
        rid = gate.get("rule_id", "")
        if rid:
            rule_ids.add(str(rid))
        counts[_DECISION_LABELS.get(_decision(payload) or "", "other")] += 1

    return {
        "agents": agents,
        "issuers": issuers,
        "operations": operations,
        "policies": policies,
        "rule_ids": rule_ids,
        "ruleset_hashes": ruleset_hashes,
        "receipt_hashes": receipt_hashes,
        "counts": counts,
        "event_times": event_times,
    }


def _governance_slots(governance_mapping: dict[str, list[str]] | None) -> dict[str, list[str]]:
    """Slot dict over GOVERNANCE_SLOTS plus any unknown framework names.

    Empty is honest and expected; an unknown framework name is kept,
    never discarded.
    """
    gov = {slot: [] for slot in GOVERNANCE_SLOTS}
    if governance_mapping is None:
        return gov
    for name, ids in sorted(governance_mapping.items()):
        gov[name] = _sorted_str_list(ids, f"governance/{name}")
    return gov


def _pq_signature_field(packet: dict, pq_private: object) -> dict:
    """OV-22: ML-DSA-65 signature over the packet digest, via raucle/pq.

    The signature covers the ``packet_content_sha256`` stamp bytes
    (``"sha256:<64 hex>"`` ascii). Added after the digest and outside the
    digest body, so the digest itself is unchanged by signing. Fails
    visibly when the raucle PQ backend is unavailable.
    """
    if _rqpq is None:
        raise ValueError("PQ signing requires the raucle package (installed dependency)")
    if not _rqpq.pq_available():
        raise ValueError(
            "ML-DSA is unavailable in this runtime (raucle PQ backend);"
            " build the packet without a PQ signature"
        )
    stamp = packet["packet_content_sha256"]
    try:
        signature = pq_private.sign(stamp.encode("ascii"))  # type: ignore[attr-defined]
        public_key = pq_private.public_key()  # type: ignore[attr-defined]
    except AttributeError as exc:
        raise ValueError(
            "pq_private must be an ML-DSA-65 private key (raucle.pq.pq_generate)"
        ) from exc
    return {
        "algorithm": _rqpq.PQ1_ALG,
        "key_id": _rqpq.pq_key_id_from_public_key(public_key),
        "public_key_hex": _rqpq.pq_public_key_hex(public_key),
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "packet_content_sha256": stamp,
    }


def build_packet(
    evidence_store: pathlib.Path,
    *,
    capability_refs: list[str] | None = None,
    policy_proof_refs: list[str] | None = None,
    governance_mapping: dict[str, list[str]] | None = None,
    risk_annotations: list[str] | None = None,
    pq_private: object | None = None,
) -> dict:
    """Compile the versioned packet. Deterministic; fail-visible on bad input.

    ``pq_private``, when given (an ML-DSA-65 private key from
    ``raucle.pq.pq_generate``), adds the optional ``packet_pq_signature``
    field: an ML-DSA-65 signature of ``packet_content_sha256`` made with
    raucle's quantum-ready primitive.
    """
    if not evidence_store.is_file():
        raise ValueError(f"evidence store not found: {evidence_store}")
    store_file_sha = SHA256_PREFIX + hashlib.sha256(evidence_store.read_bytes()).hexdigest()
    lines = read_store(evidence_store)
    s = _store_summary(lines)
    gov = _governance_slots(governance_mapping)

    packet = {
        "kind": PACKET_KIND,
        "schema_version": PACKET_SCHEMA_VERSION,
        "guard": GUARD_SENTENCE,
        "inputs": {"evidence_store_sha256": store_file_sha},
        "packet_content_sha256": "",
        "agent_identity": {
            "agents": sorted(a for a in s["agents"] if a),
            "issuers": sorted(i2 for i2 in s["issuers"] if i2),
        },
        "receipt_chain": {
            "line_count": len(lines),
            "receipt_hashes": sorted(s["receipt_hashes"]),
            "operations": dict(sorted(s["operations"].items())),
            "ruleset_hashes": sorted(s["ruleset_hashes"]),
            "first_event_time": min(s["event_times"]) if s["event_times"] else None,
            "last_event_time": max(s["event_times"]) if s["event_times"] else None,
        },
        "gate_coverage": {
            "admitted": s["counts"]["admitted"],
            "held": s["counts"]["held"],
            "refused": s["counts"]["refused"],
            "other": s["counts"]["other"],
            "without_gate": s["counts"]["without_gate"],
            "distinct_policies": sorted(s["policies"]),
            "distinct_rule_ids": sorted(s["rule_ids"]),
        },
        "capability_refs": sorted(set(capability_refs or [])),
        "policy_proof_refs": sorted(set(policy_proof_refs or [])),
        "governance_mapping": gov,
        "risk_annotations": sorted(set(risk_annotations or [])),
    }
    body = dict(packet)
    body.pop("packet_content_sha256", None)
    packet["packet_content_sha256"] = (
        SHA256_PREFIX + hashlib.sha256(canonical_json(body).encode()).hexdigest()
    )
    if pq_private is not None:
        packet["packet_pq_signature"] = _pq_signature_field(packet, pq_private)
    return packet


# ------------------------------------------------------------------ html ---


def _esc(s: object) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _list_items(values: list[str], fallback: str) -> list[str]:
    if not values:
        return [f"<li>{_esc(fallback)}</li>"]
    return [f"<li>{_esc(v)}</li>" for v in values]


def html_summary(packet: dict) -> str:
    """textContent-only HTML summary. No scripting, no inline handlers."""
    identity = packet["agent_identity"]
    gov_items = [
        f"<li>{_esc(k)}: {_esc(', '.join(v) or _UNSUPPORTED)}</li>"
        for k, v in packet["governance_mapping"].items()
    ]
    coverage_items = [f"<li>{_esc(k)}: {_esc(v)}</li>" for k, v in packet["gate_coverage"].items()]
    risk_items = _list_items(packet["risk_annotations"], "none annotated")
    lines = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        f"<title>Agent Assurance Packet (schema v{packet['schema_version']})</title>",
        "</head>",
        "<body>",
        "<h1>Agent Assurance Packet</h1>",
        "<p>Schema version: " + _esc(packet["schema_version"]) + "</p>",
        "<p>" + _esc(packet["guard"]) + "</p>",
        "<h2>Agent identity</h2>",
        "<p>Agents: " + _esc(", ".join(identity["agents"]) or _EMPTY) + "</p>",
        "<p>Issuers: " + _esc(", ".join(identity["issuers"]) or _EMPTY) + "</p>",
        "<h2>Receipt chain</h2>",
        "<p>Line count: " + _esc(packet["receipt_chain"]["line_count"]) + "</p>",
        "<p>Receipt hashes:</p><ul>",
        *_list_items(packet["receipt_chain"]["receipt_hashes"], _EMPTY),
        _CLOSE_UL,
        "<h2>Gate coverage</h2>",
        "<ul>",
        *coverage_items,
        _CLOSE_UL,
        "<h2>Capability refs</h2>",
        "<p>" + _esc(", ".join(packet["capability_refs"]) or _EMPTY_DECLARED) + "</p>",
        "<h2>Policy-proof refs</h2>",
        "<p>" + _esc(", ".join(packet["policy_proof_refs"]) or _EMPTY_DECLARED) + "</p>",
        "<h2>Governance mapping</h2>",
        "<ul>",
        *gov_items,
        _CLOSE_UL,
        "<h2>Risk annotations</h2>",
        "<ul>",
        *risk_items,
        _CLOSE_UL,
        "<h2>Integrity</h2>",
        "<p>Packet content sha256: " + _esc(packet["packet_content_sha256"]) + "</p>",
        "<p>Inputs: " + _esc(canonical_json(packet["inputs"])) + "</p>",
        "</body>",
        "</html>",
    ]
    return "\n".join(lines) + "\n"


# ------------------------------------------------------------------- cli ---


def _optional_json_list(path_str: str | None, label: str) -> list[str] | None:
    """Named JSON list file as an optional CLI input."""
    if path_str is None:
        return None
    return _sorted_str_list(
        _load_named_json(pathlib.Path(path_str).expanduser().resolve(), label), label
    )


def _load_cli_refs(args: argparse.Namespace) -> dict:
    """Operator-supplied reference files for the packet build."""
    governance = None
    gov_path = getattr(args, "governance", None)
    if gov_path is not None:
        loaded = _load_named_json(pathlib.Path(gov_path).expanduser().resolve(), "governance")
        if not isinstance(loaded, dict):
            raise ValueError("governance must be a JSON object of framework -> id list")
        governance = cast("dict[str, list[str]]", loaded)
    return {
        "capability_refs": _optional_json_list(args.capability_refs, "capability-refs"),
        "policy_proof_refs": _optional_json_list(args.policy_proof_refs, "policy-proof-refs"),
        "governance_mapping": governance,
        "risk_annotations": _optional_json_list(args.risk_annotations, "risk-annotations"),
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="OV-1: build a deterministic agent assurance packet")
    ap.add_argument("--evidence-store", required=True)
    ap.add_argument("--capability-refs", help="JSON list file of capability refs")
    ap.add_argument("--policy-proof-refs", help="JSON list file of policy-proof refs")
    ap.add_argument("--governance", help="JSON object file: framework -> crosswalk ids")
    ap.add_argument("--risk-annotations", help="JSON list file of risk annotation strings")
    ap.add_argument(
        "--pq-private-key",
        help="PEM file with an ML-DSA-65 private key; adds packet_pq_signature",
    )
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args(argv)
    try:
        refs = _load_cli_refs(args)
        if args.pq_private_key is not None:
            if _rqpq is None:
                raise ValueError("PQ signing requires the raucle package (installed dependency)")
            try:
                with open(args.pq_private_key, encoding="ascii") as pq_fh:
                    pq_private = _rqpq.pq_private_key_from_pem(pq_fh.read())
            except OSError as exc:
                raise ValueError(
                    f"pq private key not found: {args.pq_private_key} ({exc})"
                ) from exc
        else:
            pq_private = None
        packet = build_packet(
            pathlib.Path(args.evidence_store).expanduser().resolve(),
            pq_private=pq_private,
            **refs,
        )
    except ValueError as exc:
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
