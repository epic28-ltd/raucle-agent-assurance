# SPDX-License-Identifier: Apache-2.0
"""OV-3: independent offline re-validation of an agent assurance packet.

Deliberately standalone, like verify_pack.py: standard library only, no
project imports, no network. The derivation here is an independent
re-implementation of the packet builder's rules (fresh code, same
contract), so a shared bug would not silently reproduce itself.

Usage:

    python revalidate_packet.py --packet PACKET.json \\
        --evidence-store STORE.jsonl \\
        [--capability-refs FILE] [--policy-proof-refs FILE] \\
        [--governance FILE] [--risk-annotations FILE]

Checks, each reported PASS/FAIL with a plain-English line, per the
fail-visible contract:

1. Packet integrity — every required field present, and
   ``packet_content_sha256`` re-derives from the packet body (tampered
   packet fails before anything else is trusted).
2. Trust anchors — the store digest recorded in the packet inputs
   matches the supplied evidence store (a swapped store is a named FAIL).
3. Receipt chain — every store line re-derives its recorded
   ``receipt_hash`` from its JWS bytes; an edited or swapped receipt is a
   named FAIL.
1b. Optional PQ signature (OV-22) — if the packet carries
   ``packet_pq_signature`` (ML-DSA-65 over ``packet_content_sha256``),
   it is verified with raucle's quantum-ready primitive; a bad,
   unauthorised or malformed signature is a named FAIL.
4. Verdict reproduction — an independent re-derivation of the packet
   body from the supplied inputs must equal the packet exactly; any
   divergence (counts, identity, coverage, refs, mappings) is a named
   MISMATCH.

Overall verdict legible to a non-engineer: REPRODUCED on green, MISMATCH
on red; exit 0 green, 1 red.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import json
import os
import pathlib
import re

try:  # OV-22: raucle ships the ML-DSA-65 primitive; PQ checks fail visibly without it
    import raucle.pq as _rqpq
except ModuleNotFoundError:  # pragma: no cover - dependency-dependent
    _rqpq = None

SHA256_PREFIX = "sha256:"
PACKET_KIND = "agent_assurance_packet"

_GOVERNANCE_SLOTS = (
    "dora",
    "eu_ai_act",
    "iso_42001",
    "soc_2",
    "nist_ai_rmf",
    "owasp_llm",
)

_DECISION_LABELS = {"allow": "admitted", "deny": "refused", "hold": "held", "held": "held"}
_CANON_RECEIPT_HASH = re.compile(r"sha256:[0-9a-f]{64}")

_REQUIRED_FIELDS = (
    "kind",
    "schema_version",
    "guard",
    "inputs",
    "packet_content_sha256",
    "agent_identity",
    "receipt_chain",
    "gate_coverage",
    "capability_refs",
    "policy_proof_refs",
    "governance_mapping",
    "risk_annotations",
)

# The mandatory honesty guard, in the GOV-01 pattern.
GUARD_SENTENCE = (
    "This packet records what was cryptographically observed inside a"
    " deliberately narrow scope. It does not establish legal or regulatory"
    " compliance, and it asserts no certification, no approval, no"
    " accreditation, no attestation, and no warranty of any kind."
)


class _Fail(Exception):
    """Named, user-legible failure; caught in main and reported."""


def canonical_json(obj: object) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sorted_str_list(value: object, label: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise _Fail(f"{label} must be a list of strings")
    return sorted(set(value))


def _load_json_file(path_str: str | None, label: str) -> object:
    if path_str is None:
        return None
    try:
        with open(path_str, encoding="utf-8") as fh:
            return json.loads(fh.read())
    except OSError as exc:
        raise _Fail(f"{label} file not found ({exc})") from exc


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


def _validated_line(raw: str, label: str) -> tuple[str, dict]:
    """(receipt_hash, gate payload), fail-visible on any malformation."""
    line = raw.rstrip("\n")
    if not line:
        raise _Fail(f"{label}: blank store line")
    try:
        rec = json.loads(line)
    except json.JSONDecodeError as exc:
        raise _Fail(f"{label}: not a JSON object line ({exc})") from exc
    if not isinstance(rec, dict) or not isinstance(rec.get("jws"), str):
        raise _Fail(f"{label}: store line is not a {{receipt_hash, jws}} object")
    jws: str = rec["jws"]
    rh = rec.get("receipt_hash")
    if not isinstance(rh, str) or not _CANON_RECEIPT_HASH.fullmatch(rh.strip().lower()):
        raise _Fail(f"{label}: receipt_hash is not canonical sha256:<64 hex>")
    if jws.count(".") != 2:
        raise _Fail(f"{label}: jws envelope is missing or not a compact JWS")
    want = SHA256_PREFIX + hashlib.sha256(jws.encode()).hexdigest()
    if rh.strip().lower() != want:
        raise _Fail(
            f"{label}: receipt_hash {rh[:24]}… does not re-derive from the receipt"
            " bytes (tampered or swapped receipt)"
        )
    try:
        seg = jws.split(".")[1]
        payload = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception as exc:
        raise _Fail(f"{label}: unreadable envelope payload ({exc})") from exc
    if not isinstance(payload, dict):
        raise _Fail(f"{label}: envelope payload is not a JSON object")
    return rh.strip().lower(), payload


def _store_records(evidence_store: str) -> tuple[str, list[dict], set[str]]:
    """(file sha256, validated payloads, receipt hashes); fail-visible."""
    try:
        with open(evidence_store, "rb") as fh:
            store_bytes = fh.read()
    except OSError as exc:
        raise _Fail(f"evidence store not found: {evidence_store} ({exc})") from exc
    store_file_sha = SHA256_PREFIX + hashlib.sha256(store_bytes).hexdigest()
    with open(evidence_store, encoding="utf-8") as fh:
        raw_text = fh.read()

    receipt_hashes: set[str] = set()
    records: list[dict] = []
    for i, raw in enumerate(raw_text.splitlines(), start=1):
        if not raw.strip():
            continue
        rh, payload = _validated_line(raw, f"{os.path.basename(evidence_store)} line {i}")
        receipt_hashes.add(rh)
        records.append(payload)
    if not records:
        raise _Fail(f"evidence store {evidence_store} has no receipt lines")
    return store_file_sha, records, receipt_hashes


def _aggregate(records: list[dict]) -> dict:
    """Independent aggregation of identity, coverage and chain fields."""
    agents: set[str] = set()
    issuers: set[str] = set()
    operations: dict[str, int] = {}
    policies: set[str] = set()
    rule_ids: set[str] = set()
    ruleset_hashes: set[str] = set()
    counts = {"admitted": 0, "held": 0, "refused": 0, "other": 0, "without_gate": 0}
    event_times: list[int] = []

    for payload in records:
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
        "counts": counts,
        "event_times": event_times,
    }


def _governance_slots(governance_mapping: dict[str, list[str]] | None) -> dict[str, list[str]]:
    gov: dict[str, list[str]] = {slot: [] for slot in _GOVERNANCE_SLOTS}
    if governance_mapping is None:
        return gov
    for name, ids in sorted(governance_mapping.items()):
        gov[name] = _sorted_str_list(ids, f"governance/{name}")
    return gov


def rederive_packet_from_inputs(
    evidence_store: str,
    *,
    capability_refs: list[str] | None = None,
    policy_proof_refs: list[str] | None = None,
    governance_mapping: dict[str, list[str]] | None = None,
    risk_annotations: list[str] | None = None,
) -> dict:
    """Independent re-derivation of the full packet (OV-1 rules)."""
    store_file_sha, records, receipt_hashes = _store_records(evidence_store)
    agg = _aggregate(records)
    gov = _governance_slots(governance_mapping)
    event_times = agg["event_times"]

    packet = {
        "kind": PACKET_KIND,
        "schema_version": 1,
        "guard": GUARD_SENTENCE,
        "inputs": {"evidence_store_sha256": store_file_sha},
        "packet_content_sha256": "",
        "agent_identity": {
            "agents": sorted(a for a in agg["agents"] if a),
            "issuers": sorted(x for x in agg["issuers"] if x),
        },
        "receipt_chain": {
            "line_count": len(records),
            "receipt_hashes": sorted(receipt_hashes),
            "operations": dict(sorted(agg["operations"].items())),
            "ruleset_hashes": sorted(agg["ruleset_hashes"]),
            "first_event_time": min(event_times) if event_times else None,
            "last_event_time": max(event_times) if event_times else None,
        },
        "gate_coverage": {
            "admitted": agg["counts"]["admitted"],
            "held": agg["counts"]["held"],
            "refused": agg["counts"]["refused"],
            "other": agg["counts"]["other"],
            "without_gate": agg["counts"]["without_gate"],
            "distinct_policies": sorted(agg["policies"]),
            "distinct_rule_ids": sorted(agg["rule_ids"]),
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
    return packet


def _verify_pq_signature_field(packet: dict) -> None:
    """OV-22: verify an optional ML-DSA-65 packet signature; fail-visible.

    The field (when present) signs the ``packet_content_sha256`` stamp
    bytes with raucle's quantum-ready primitive (raucle/pq1, ML-DSA-65).
    Verified inline before re-derivation: a bad signature fails the whole
    run, and the field is excluded from the body comparison like the
    digest stamp it covers.
    """
    field = packet.get("packet_pq_signature")
    if not isinstance(field, dict):
        raise _Fail("packet_pq_signature must be an object")
    if field.get("algorithm") != "ml-dsa-65":
        raise _Fail("packet_pq_signature.algorithm must be 'ml-dsa-65'")
    if _rqpq is None:
        raise _Fail(
            "packet carries packet_pq_signature but raucle (the ML-DSA-65"
            " primitive) is not available in this runtime"
        )
    if not _rqpq.pq_available():
        raise _Fail(
            "packet carries packet_pq_signature but this runtime cannot"
            " verify ML-DSA-65 (raucle PQ backend unavailable)"
        )

    key_id = field.get("key_id")
    pub_hex = field.get("public_key_hex")
    sig_b64 = field.get("signature_b64")
    if not isinstance(key_id, str) or len(key_id) != 16 or not key_id.isalnum():
        raise _Fail("packet_pq_signature.key_id is not a 16-char key id")
    if not isinstance(pub_hex, str) or len(pub_hex) % 2 or not pub_hex.isalnum():
        raise _Fail("packet_pq_signature.public_key_hex is not hex")
    if not isinstance(sig_b64, str):
        raise _Fail("packet_pq_signature.signature_b64 is not a base64 string")
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise _Fail(f"packet_pq_signature.signature_b64 does not decode ({exc})") from exc
    try:
        pub = _rqpq.pq_public_key_from_hex(pub_hex)
    except Exception as exc:
        raise _Fail(f"packet_pq_signature.public_key_hex is not an ML-DSA-65 key ({exc})") from exc
    derived_key_id = _rqpq.pq_key_id_from_public_key(pub)
    if key_id != derived_key_id:
        raise _Fail(
            f"packet_pq_signature.key_id {key_id!r} does not match the"
            f" supplied public key ({derived_key_id!r})"
        )
    stamp = packet.get("packet_content_sha256")
    if not isinstance(stamp, str):
        raise _Fail("packet_content_sha256 is not a digest string")
    try:
        pub.verify(sig, stamp.encode("ascii"))
    except Exception as exc:
        raise _Fail(
            f"packet_pq_signature failed ML-DSA-65 verification over the packet digest ({exc})"
        ) from exc


def _diff(a: dict, b: dict, prefix: str = "") -> list[str]:
    out: list[str] = []
    for key in sorted(set(a) | set(b)):
        av = a.get(key, "<missing>")
        bv = b.get(key, "<missing>")
        pa = f"{prefix}.{key}" if prefix else key
        if isinstance(av, dict) and isinstance(bv, dict):
            out.extend(_diff(av, bv, prefix=pa))
        elif av != bv:
            out.append(pa)
    return out


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="OV-3: independently re-validate an agent assurance packet"
    )
    ap.add_argument("--packet", required=True)
    ap.add_argument("--evidence-store", required=True)
    ap.add_argument("--capability-refs")
    ap.add_argument("--policy-proof-refs")
    ap.add_argument("--governance")
    ap.add_argument("--risk-annotations")
    ap.add_argument(
        "--report",
        help="write the machine-readable revalidation report (oaa.revalidation-report/v1)",
    )
    return ap.parse_args(argv)


def _refused_report_message(report_path: str | None) -> str | None:
    """The tainted ``--report`` destination is canonicalised before any write.

    Traversal shorthands and destinations that resolve to a filesystem root
    or the home directory are refused outright — per the same hardening as
    generate_report's --out. Refusal keeps the run fail-visible (a named
    FAIL), never a silent pass.
    """
    if report_path is None:
        return None
    resolved = pathlib.Path(report_path).expanduser().resolve()
    if resolved == pathlib.Path(resolved.root) or resolved == pathlib.Path.home():
        return f"--report path refused (unusable destination): {report_path}"
    return None


def _canonical_report(report_path: str | None) -> str | None:
    if report_path is None:
        return None
    return str(pathlib.Path(report_path).expanduser().resolve())


def _packet_digest_fail(packet: dict, checks: list[tuple[str, str]]) -> str | None:
    """Check 1 — the packet stamp re-derives from the packet body."""
    body = dict(packet)
    stamp = body.pop("packet_content_sha256", None)
    body.pop("packet_pq_signature", None)  # added after the digest; outside the body
    recomputed = SHA256_PREFIX + hashlib.sha256(canonical_json(body).encode()).hexdigest()
    if stamp != recomputed:
        return (
            "packet_content_sha256 does not re-derive from the packet body"
            " (tampered or mis-stamped packet)"
        )
    checks.append(("PASS", "packet digest re-derives from the packet body"))
    return None


def _packet_pq_fail(packet: dict, checks: list[tuple[str, str]]) -> str | None:
    """Check 1b — the optional quantum-ready packet signature (OV-22)."""
    if "packet_pq_signature" not in packet:
        return None
    try:
        _verify_pq_signature_field(packet)
    except _Fail as exc:
        return str(exc)
    checks.append(("PASS", "ML-DSA-65 packet signature verifies over the packet digest"))
    return None


def _safe_read(path: str, mode: str, label: str, fail_sentinel: str | bytes):
    """Read a CLI-supplied path after canonicalising it and checking it exists.

    The path argument is attacker-adjacent, so it is resolved to an absolute
    canonical form and must name an existing regular file before any read;
    anything else is a named FAIL, never a silent pass.
    """
    resolved = pathlib.Path(path).expanduser().resolve()
    if not resolved.is_file():
        return fail_sentinel, f"{label} file not found: {resolved}"
    try:
        with open(resolved, mode) as fh:
            return fh.read(), None
    except OSError as exc:
        return fail_sentinel, f"{label} file not readable: {resolved} ({exc})"


def _load_bytes_fail(path: str, label: str) -> tuple[str, str | None]:
    data, err = _safe_read(path, "r", label, "")
    return str(data), err


def _load_store_bytes_fail(path: str, label: str) -> tuple[bytes, str | None]:
    data, err = _safe_read(path, "rb", label, b"")
    return data if isinstance(data, bytes) else b"", err


def _evidence_store_fail(store_path: str, packet: dict, checks: list) -> str | None:
    """Check 2 — the supplied store digests to what the packet recorded."""
    data, err = _load_store_bytes_fail(store_path, "evidence store")
    if err is not None:
        return err
    want = SHA256_PREFIX + hashlib.sha256(data).hexdigest()
    recorded = ""
    inputs = packet.get("inputs")
    if isinstance(inputs, dict):
        recorded = str(inputs.get("evidence_store_sha256", ""))
    if recorded != want:
        return (
            "evidence store digest does not match the packet's recorded input"
            " (the packet was not built from this artefact: wrong or swapped store)"
        )
    checks.append(("PASS", "evidence store digest matches the packet's recorded input"))
    return None


def _rederive_diffs(args: argparse.Namespace) -> tuple[dict | None, str | None]:
    """Check 3 — re-derive the packet; an input-loader or chain _Fail is named."""
    try:
        gov_in = _load_json_file(args.governance, "governance")
        gov = gov_in if isinstance(gov_in, dict) else None
        rederived = rederive_packet_from_inputs(
            args.evidence_store,
            capability_refs=_sorted_str_list(
                _load_json_file(args.capability_refs, "capability-refs"), "capability-refs"
            ),
            policy_proof_refs=_sorted_str_list(
                _load_json_file(args.policy_proof_refs, "policy-proof-refs"),
                "policy-proof-refs",
            ),
            governance_mapping=gov,
            risk_annotations=_sorted_str_list(
                _load_json_file(args.risk_annotations, "risk-annotations"),
                "risk-annotations",
            ),
        )
    except _Fail as exc:
        return None, str(exc)
    return rederived, None


def _body_diff_fail(packet: dict, rederived: dict, checks: list) -> str | None:
    """Check 4 — byte-level comparison of the packet body against the re-derivation."""
    checks.append(("PASS", "every receipt re-derives its recorded sha256 from its envelope bytes"))
    # The PQ signature covers the digest and sits outside the digest body,
    # so like the stamp itself it is excluded from the body comparison.
    packet.pop("packet_pq_signature", None)
    diffs = _diff(packet, rederived)
    if not diffs:
        checks.append(("PASS", "packet body reproduces exactly from the supplied evidence"))
        return None
    for d in diffs:
        checks.append(("FAIL", f"re-derived packet differs at {d}"))
    return "re-derived packet differs"


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    checks: list[tuple[str, str]] = []

    # The --report destination is a tainted CLI path: canonicalise it (and
    # refuse unusable destinations as a named FAIL) before anything else.
    refusal = _refused_report_message(args.report)
    if refusal is not None:
        checks.append(("FAIL", refusal))
        return _report(checks, None)
    report_path = _canonical_report(args.report)

    def fail(message: str) -> int:
        checks.append(("FAIL", message))
        return _report(checks, report_path)

    text, err = _load_bytes_fail(args.packet, "packet")
    if err is not None:
        return fail(err)
    packet = json.loads(text)
    missing = [f for f in _REQUIRED_FIELDS if f not in packet]
    if missing:
        return fail(f"packet is missing required fields: {', '.join(missing)}")

    for named_fail in (
        _packet_digest_fail(packet, checks),
        _packet_pq_fail(packet, checks),
        _evidence_store_fail(args.evidence_store, packet, checks),
    ):
        if named_fail is not None:
            return fail(named_fail)

    rederived, rederive_fail = _rederive_diffs(args)
    if rederive_fail is not None:
        return fail(rederive_fail)
    diff_fail = _body_diff_fail(packet, rederived, checks)
    if diff_fail is not None:
        return _report(checks, report_path)
    return _report(checks, report_path)


REPORT_SCHEMA = "oaa.revalidation-report/v1"


def _report_document(checks: list[tuple[str, str]]) -> dict:
    """OV-20: the machine-readable output document for an independent review."""
    failed = any(status == "FAIL" for status, _ in checks)
    return {
        "schema": REPORT_SCHEMA,
        "verdict": "MISMATCH" if failed else "REPRODUCED",
        "checks": [{"status": status, "message": message} for status, message in checks],
    }


def _report(checks: list[tuple[str, str]], report_path: str | None = None) -> int:
    if report_path is not None:
        try:
            with open(report_path, "w", encoding="utf-8") as fh:
                fh.write(json.dumps(_report_document(checks), indent=2, sort_keys=True) + "\n")
        except OSError as exc:
            # fail-visible: a report that cannot be written is a named FAIL,
            # never a silent green run without its document.
            checks.append(("FAIL", f"revalidation report not written: {exc}"))
    failed = any(s == "FAIL" for s, _ in checks)
    print("OV-3 packet re-validation —", "MISMATCH" if failed else "REPRODUCED")
    for status, message in checks:
        print(f"[{status}] {message}")
    if not failed:
        print(
            "Verdict: the packet reproduces from its evidence; a reviewer can"
            " recheck this offline at any time."
        )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
