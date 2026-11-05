# SPDX-License-Identifier: Apache-2.0
"""OV-22: optional ML-DSA-65 packet signature over the packet digest.

A packet may carry ``packet_pq_signature`` — an ML-DSA-65 (FIPS 204)
signature of the ``packet_content_sha256`` stamp made with raucle's
quantum-ready primitive. Optional: without the key the packet is exactly
the OV-1 artifact; with the key the signature is added after the digest,
outside the digest body, and the independent revalidator (tests/
verifier/test_revalidate_packet.py) verifies it.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest

pytest.importorskip("raucle")
import raucle.pq as rqpq

if not rqpq.pq_available():  # pragma: no cover - backend-dependent
    pytest.skip("ML-DSA unavailable in this runtime", allow_module_level=True)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO_STORE = REPO_ROOT / "services" / "investigation-ui" / "demo_data" / "evidence_store.jsonl"


def _load_module(name: str, relpath: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relpath)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


packet = _load_module("oaa_ov22_packet", "services/assurance_packet/packet.py")
rv = _load_module("oaa_ov22_rv", "tools/verifier/revalidate_packet.py")


def _signed_packet() -> tuple[dict, object, dict]:
    pq_priv, _, _ = rqpq.pq_generate()
    plain = packet.build_packet(DEMO_STORE)
    signed = packet.build_packet(DEMO_STORE, pq_private=pq_priv)
    return signed, pq_priv, plain


def test_pq_field_present_digest_unchanged() -> None:
    signed, _, plain = _signed_packet()
    assert signed["packet_content_sha256"] == plain["packet_content_sha256"]
    field = signed["packet_pq_signature"]
    assert field["algorithm"] == "ml-dsa-65"
    assert len(field["key_id"]) == 16
    assert field["packet_content_sha256"] == plain["packet_content_sha256"]
    assert isinstance(base64.b64decode(field["signature_b64"], validate=True), bytes)
    # optional elsewhere: plain packet stays exactly the OV-1 shape
    assert "packet_pq_signature" not in plain


def test_signed_field_is_outside_digest_body() -> None:
    signed, _, _ = _signed_packet()
    body = dict(signed)
    body.pop("packet_content_sha256")
    body.pop("packet_pq_signature")
    stamp = packet.SHA256_PREFIX + hashlib.sha256(packet.canonical_json(body).encode()).hexdigest()
    assert signed["packet_content_sha256"] == stamp


def test_signing_same_key_same_digest_verifies() -> None:
    # ML-DSA signs with per-call randomised padding, so signatures differ
    # between runs; the digest both cover is identical and each verifies.
    pq_priv, _, _ = rqpq.pq_generate()
    a = packet.build_packet(DEMO_STORE, pq_private=pq_priv)
    b = packet.build_packet(DEMO_STORE, pq_private=pq_priv)
    assert a["packet_content_sha256"] == b["packet_content_sha256"]
    assert b["packet_pq_signature"]["signature_b64"] != a["packet_pq_signature"]["signature_b64"]
    assert rv._verify_pq_signature_field(a) is None
    assert rv._verify_pq_signature_field(b) is None


def test_cli_revalidator_reproduces_signed_packet(tmp_path: pathlib.Path) -> None:
    signed, _, _ = _signed_packet()
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n")
    rc = rv.main(["--packet", str(packet_path), "--evidence-store", str(DEMO_STORE)])
    assert rc == 0


def test_cli_revalidator_fails_named_on_tampered_body(tmp_path: pathlib.Path) -> None:
    signed, _, _ = _signed_packet()
    tampered = json.loads(json.dumps(signed))
    tampered["risk_annotations"] = ["tampered"]
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(tampered) + "\n")
    rc = rv.main(["--packet", str(packet_path), "--evidence-store", str(DEMO_STORE)])
    assert rc == 1


def test_verify_field_directly_roundtrip(tmp_path: pathlib.Path) -> None:
    signed, _, _ = _signed_packet()
    rv._verify_pq_signature_field(signed)  # must not raise


def test_verify_field_named_failures(tmp_path: pathlib.Path) -> None:
    signed, _, _ = _signed_packet()
    with pytest.raises(rv._Fail, match="digest"):
        bad = json.loads(json.dumps(signed))
        bad["packet_content_sha256"] = "sha256:" + "0" * 64
        rv._verify_pq_signature_field(bad)
    with pytest.raises(rv._Fail, match="key_id"):
        bad = json.loads(json.dumps(signed))
        bad["packet_pq_signature"]["key_id"] = "0" * 16
        rv._verify_pq_signature_field(bad)
    with pytest.raises(rv._Fail, match="ML-DSA"):
        bad = json.loads(json.dumps(signed))
        field = bad["packet_pq_signature"]
        raw = bytearray(base64.b64decode(field["signature_b64"]))
        raw[0] ^= 0xFF
        field["signature_b64"] = base64.b64encode(bytes(raw)).decode()
        rv._verify_pq_signature_field(bad)
    with pytest.raises(rv._Fail, match="algorithm"):
        bad = json.loads(json.dumps(signed))
        bad["packet_pq_signature"]["algorithm"] = "rsa-pss"
        rv._verify_pq_signature_field(bad)
    with pytest.raises(rv._Fail, match="base64"):
        bad = json.loads(json.dumps(signed))
        bad["packet_pq_signature"]["signature_b64"] = "!!! not base64 !!!"
        rv._verify_pq_signature_field(bad)


def test_diff_excludes_pq_field() -> None:
    signed, _, _ = _signed_packet()
    # the revalidator must strip the field before comparing against the
    # re-derived body (which never carries it)
    stripped = dict(signed)
    stripped.pop("packet_pq_signature")
    rederived = rv.rederive_packet_from_inputs(DEMO_STORE)
    assert rv._diff(stripped, rederived) == []
