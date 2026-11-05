# SPDX-License-Identifier: Apache-2.0
"""Pack replay binding: happy path and honest mismatch paths.

The replay renders a decision from the audit pack alone. Its honesty
contract: a hop/graph the pack cannot resolve is stated as unresolved or
absent, never inferred valid; a receipt absent from the pack cannot be
replayed (LookupError, never a guess); signature verification against the
pinned snapshot is real Ed25519, with unknown_key / invalid states, and a
missing crypto dependency is the unreachable state — never a silent pass.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import pathlib
import sys

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oaa_raucle_adapter.replay import replay_receipt_from_pack

KID = "0123456789abcdef"


def _mint(iat: int, kid: str = KID, agent: str = "agent:gw") -> tuple[dict, str, str]:
    """(trust-root row, envelope line, receipt_hash)."""
    key = Ed25519PrivateKey.generate()
    pem = (
        key.public_key()
        .public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    row = {
        "key_id": kid,
        "public_key_pem": pem,
        "valid_from": "1970-01-01T00:00:00+00:00",
        "valid_until": None,
        "status": "current",
    }
    hp = (
        base64.urlsafe_b64encode(
            json.dumps({"alg": "EdDSA", "kid": kid, "typ": "provenance-receipt/v1"}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    body = {
        "agent_id": agent,
        "iat": iat,
        "guardrail_verdict": "allow",
        "ruleset_hash": "sha256:" + "cd" * 32,
    }
    pp = (
        base64.urlsafe_b64encode(
            json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    sig = base64.urlsafe_b64encode(key.sign(f"{hp}.{pp}".encode())).rstrip(b"=").decode()
    jws = f"{hp}.{pp}.{sig}"
    rh = "sha256:" + hashlib.sha256(jws.encode()).hexdigest()
    return row, json.dumps({"receipt_hash": rh, "jws": jws}), rh


def _pack(
    tmp_path: pathlib.Path,
    *,
    receipts: list[str],
    roots: list[dict],
    graph: dict | None = None,
    raw_receipt_lines: list[str] | None = None,
    policies_dir: bool = True,
) -> pathlib.Path:
    d = tmp_path / "pack"
    d.mkdir()
    (d / "receipts.jsonl").write_text(
        "".join(ln + "\n" for ln in (raw_receipt_lines if raw_receipt_lines is not None else receipts))
    )
    keys = d / "keys"
    keys.mkdir()
    (keys / "trust_roots.jsonl").write_text("".join(json.dumps(r) + "\n" for r in roots))
    if graph is not None:
        (d / "chain_graph.json").write_text(json.dumps(graph))
    if policies_dir:
        pol = d / "policies"
        pol.mkdir()
        (pol / "baseline.yaml").write_text("rules: []\n")
    return d


IAT = int(dt.datetime(2026, 11, 5, 12, 0, tzinfo=dt.UTC).timestamp())


def _resolved_graph_doc(rh: str) -> dict:
    """The chain_graph.json document shape: one graph keyed by receipt hash."""
    return {"status": "resolved-by-pinned-verifier", "graphs": {rh: _resolved_graph(rh)}}


def _resolved_graph(rh: str) -> dict:
    """A resolved graph with a policy binding and a two-hop delegation chain."""
    return {
        "status": "resolved-by-pinned-verifier",
        "nodes": [
            {"id": rh, "kind": "receipt", "signature": {"status": "verified"},
             "gate": {"decision": "allow", "agent_id": "agent:gw"}},
            {
                "id": "policy:base",
                "kind": "policy",
                "binding_state": "bound",
                "policy_ref": "baseline-v1",
                "rule_id": "SEC-010",
                "ruleset_hash": "sha256:" + "cd" * 32,
                "deployments": [{"policy_id": "baseline-v1", "version": 3}],
            },
            {
                "id": "delegation:1",
                "kind": "delegation",
                "constraints": {"tool": "payments", "amount_limit": 100},
            },
            {
                "id": "delegation:2",
                "kind": "delegation",
                "constraints": {"tool": "payments", "amount_limit": 10},
            },
        ],
        "edges": [
            {"kind": "policy_binding", "from": rh, "to": "policy:base"},
            {"kind": "delegation_parent", "from": "delegation:2", "to": "delegation:1"},
        ],
    }


# --------------------------------------------------------------- happy path ----


def test_binding_happy_path_renders_resolved_replay(tmp_path: pathlib.Path) -> None:
    row, line, rh = _mint(IAT)
    d = _pack(tmp_path, receipts=[line], roots=[row], graph=_resolved_graph_doc(rh))
    out = replay_receipt_from_pack(d, rh)
    assert out["decision"]["state"] == "resolved"
    assert out["decision"]["decision"] == "allow"
    assert out["decision"]["agent_id"] == "agent:gw"
    assert out["authority_chain"]["graph_status"] == "resolved-by-pinned-verifier"
    # policy binding: the deployment event names the version in force
    pol = out["policy"]
    assert pol["binding_state"] == "bound"
    assert pol["version_in_force"]["policy_id"] == "baseline-v1"
    assert pol["version_in_force"]["version"] == 3
    assert pol["version_in_force"]["matched_by"] == "deployment_event"
    assert pol["version_in_force"]["text_available"] is True  # the policy files ship
    assert "baseline.yaml" in pol["policy_files_in_pack"]
    # hops: two delegation nodes, narrowed from parent, proof honestly absent
    hops = out["hops"]
    # from=child, to=parent: the chain starts at the most-delegated hop
    assert [h["id"] for h in hops] == ["delegation:2", "delegation:1"]
    narrowed = hops[0]["narrowed_from_parent"]
    assert narrowed == {"added": {}, "removed": [], "changed": {"amount_limit": {"from": 100, "to": 10}}}
    assert all(h["proof"]["state"] == "no_proof_recorded" for h in hops)
    # verify states agree with the graph's own signature state
    assert out["verify"][0]["verify"] == "valid"
    assert out["verify"][0]["graph_signature_state"] == {"status": "verified"}
    # proof section names the honest TODO rather than faking a proof
    assert out["proofs"][0]["state"] == "no_proof_recorded"
    ts = out["timestamps"]
    assert ts[0]["anchoring"] == "signed_iat_only"


def test_timestamp_anchoring_names_rfc3161_token(tmp_path: pathlib.Path) -> None:
    row, line, _rh = _mint(IAT)
    rec = json.loads(line)
    h, pay, _sig = rec["jws"].split(".")
    body = json.loads(base64.urlsafe_b64decode(pay + "=" * (-len(pay) % 4)))
    body["x_timestamp"] = {"mode": "tsa", "token": base64.b64encode(b"DER").decode()}
    nb = base64.urlsafe_b64encode(
        json.dumps(body, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=")
    nb = nb.decode()
    key = Ed25519PrivateKey.generate()
    row["public_key_pem"] = (
        key.public_key()
        .public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    ns = base64.urlsafe_b64encode(key.sign(f"{h}.{nb}".encode())).rstrip(b"=").decode()
    jws2 = f"{h}.{nb}.{ns}"
    rh2 = "sha256:" + hashlib.sha256(jws2.encode()).hexdigest()
    line2 = json.dumps({"receipt_hash": rh2, "jws": jws2})
    d = _pack(tmp_path, receipts=[line2], roots=[row], graph=_resolved_graph_doc(rh2))
    out = replay_receipt_from_pack(d, rh2)
    assert out["timestamps"][0]["anchoring"] == "rfc3161_token_in_pack"


def test_audit_event_nodes_join_the_timestamp_line(tmp_path: pathlib.Path) -> None:
    row, line, rh = _mint(IAT)
    graph = _resolved_graph_doc(rh)
    graph["graphs"][rh]["nodes"].append({"id": "audit:1", "kind": "audit_event", "event_timestamp": "2026-11-06T09:00:00+00:00"})
    d = _pack(tmp_path, receipts=[line], roots=[row], graph=graph)
    ts = replay_receipt_from_pack(d, rh)["timestamps"]
    assert any(t["kind"] == "audit_event" and t["id"] == "audit:1" for t in ts)
    at_list = [t["at"] for t in ts]
    assert at_list == sorted(at_list)


# ------------------------------------------------- receipt without its trace ----


def test_receipt_without_graph_states_graph_absent_honestly(tmp_path: pathlib.Path) -> None:
    """receipt-without-trace: the replay renders only what the envelope
    itself proves; it never dresses the missing graph up as resolution."""
    row, line, rh = _mint(IAT)
    d = _pack(tmp_path, receipts=[line], roots=[row], graph=None)
    out = replay_receipt_from_pack(d, rh)
    assert out["decision"]["state"] == "graph_absent"
    assert out["decision"]["decision"] == "allow"  # from the signed payload only
    assert out["authority_chain"]["graph_status"] == "absent"
    assert out["policy"]["binding_state"] == "unbound"
    assert out["hops"][0]["state"] == "unresolved"
    assert "cannot be reconstructed offline" in out["hops"][0]["honest_note"]
    assert out["verify"][0]["verify"] == "valid"  # crypto still runs


def test_unreadable_graph_is_reported_not_implied(tmp_path: pathlib.Path) -> None:
    row, line, rh = _mint(IAT)
    d = _pack(tmp_path, receipts=[line], roots=[row], graph=None)
    (d / "chain_graph.json").write_text("{broken")
    out = replay_receipt_from_pack(d, rh)
    assert out["authority_chain"]["graph_status"] == "unreadable"
    (d / "chain_graph.json").write_text('["not-a-doc"]')
    out = replay_receipt_from_pack(d, rh)
    assert out["authority_chain"]["graph_status"] == "invalid"


# ------------------------------------------------ trace without its receipt ----


def test_trace_without_receipt_cannot_be_replayed(tmp_path: pathlib.Path) -> None:
    """trace-without-receipt: a hash the pack does not hold raises; nothing
    is inferred from name coincidence."""
    row, line, _rh = _mint(IAT)
    d = _pack(tmp_path, receipts=[line], roots=[row], graph=None)
    with pytest.raises(LookupError):
        replay_receipt_from_pack(d, "sha256:" + "ff" * 32)
    # receipts.jsonl missing entirely is the same honest refusal
    empty = tmp_path / "no-receipts-pack"
    empty.mkdir()
    with pytest.raises(LookupError):
        replay_receipt_from_pack(empty, "sha256:" + "ff" * 32)


def test_undecodable_receipt_lines_are_skipped_not_replayed(tmp_path: pathlib.Path) -> None:
    row, line, rh = _mint(IAT)
    d = _pack(tmp_path, receipts=[], roots=[row], raw_receipt_lines=["{garbage", line])
    out = replay_receipt_from_pack(d, rh)
    assert out["decision"]["state"] == "graph_absent"
    with pytest.raises(LookupError):
        replay_receipt_from_pack(d, "sha256:" + "ee" * 32)


# --------------------------------------------------- signature mismatch paths ----


def test_swapped_receipt_hash_is_invalid_never_valid(tmp_path: pathlib.Path) -> None:
    _row, line, _rh = _mint(IAT)
    rec = json.loads(line)
    rec["receipt_hash"] = "sha256:" + "ab" * 32
    d = _pack(tmp_path, receipts=[json.dumps(rec)], roots=[_row], graph=_resolved_graph_doc(rec["receipt_hash"]))
    out = replay_receipt_from_pack(d, rec["receipt_hash"])
    assert out["verify"][0]["verify"] == "invalid"


def test_unknown_signing_key_is_unknown_key(tmp_path: pathlib.Path) -> None:
    _row, line, _rh = _mint(IAT)
    d = _pack(tmp_path, receipts=[line], roots=[], graph=None)  # empty snapshot
    (d / "receipts.jsonl").write_text(line + "\n")
    out = replay_receipt_from_pack(d, json.loads(line)["receipt_hash"])
    assert out["verify"][0]["verify"] == "unknown_key"


def test_forged_signature_is_invalid(tmp_path: pathlib.Path) -> None:
    row, line, _rh = _mint(IAT)
    rec = json.loads(line)
    h, pay, sig = rec["jws"].split(".")
    forged_sig = ("A" if sig[0] != "A" else "B") + sig[1:]
    jws2 = f"{h}.{pay}.{forged_sig}"
    rec2 = {"receipt_hash": "sha256:" + hashlib.sha256(jws2.encode()).hexdigest(), "jws": jws2}
    line2 = json.dumps(rec2)
    d = _pack(tmp_path, receipts=[line2], roots=[row], graph=_resolved_graph_doc(rec2["receipt_hash"]))
    out = replay_receipt_from_pack(d, rec2["receipt_hash"])
    assert out["verify"][0]["verify"] == "invalid"


def test_malformed_jws_is_invalid(tmp_path: pathlib.Path) -> None:
    row, _line, rh = _mint(IAT)
    d = _pack(tmp_path, receipts=[], roots=[row])
    (d / "receipts.jsonl").write_text(json.dumps({"receipt_hash": rh, "jws": "oops"}) + "\n")
    out = replay_receipt_from_pack(d, rh)
    assert out["verify"][0]["verify"] == "invalid"


def test_missing_crypto_dependency_is_unreachable_never_pass(tmp_path: pathlib.Path, monkeypatch) -> None:
    row, line, rh = _mint(IAT)
    d = _pack(tmp_path, receipts=[line], roots=[row], graph=None)
    for name in [
        k for k in sys.modules if k == "cryptography" or k.startswith("cryptography.")
    ]:
        monkeypatch.setitem(sys.modules, name, None)
    out = replay_receipt_from_pack(d, rh)
    assert out["verify"][0]["verify"] == "unreachable"


def test_delegation_chain_cycles_are_cut_and_late_nodes_appended(tmp_path: pathlib.Path) -> None:
    row, line, rh = _mint(IAT)
    graph = _resolved_graph_doc(rh)
    graph["graphs"][rh]["edges"].append({"kind": "delegation_parent", "from": "delegation:1", "to": "delegation:2"})
    d = _pack(tmp_path, receipts=[line], roots=[row], graph=graph)
    out = replay_receipt_from_pack(d, rh)
    ids = [h["id"] for h in out["hops"]]
    assert set(ids) == {"delegation:1", "delegation:2"}  # cycle did not loop
    assert len(ids) == 2
