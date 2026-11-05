# SPDX-License-Identifier: Apache-2.0
"""OV-22: optional ML-DSA-65 packet signature over the packet digest.

A packet may carry ``packet_pq_signature`` — an ML-DSA-65 (FIPS 204)
signature of the ``packet_content_sha256`` stamp made with raucle's
quantum-ready primitive. Optional: without the key the packet is exactly
the OV-1 artifact; with the key the signature is added after the digest,
outside the digest body, and the independent revalidator (tests/
verifier/test_revalidate_packet.py) verifies it fail-visibly.
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
    assert spec is not None
    assert spec.loader is not None
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


def test_plain_packet_has_no_pq_field() -> None:
    _, _, plain = _signed_packet()
    assert "packet_pq_signature" not in plain


def test_pq_field_present_digest_unchanged() -> None:
    signed, _, plain = _signed_packet()
    field = signed["packet_pq_signature"]
    assert field["algorithm"] == "ml-dsa-65"
    assert field["packet_content_sha256"] == plain["packet_content_sha256"]
    assert signed["packet_content_sha256"] == plain["packet_content_sha256"]


def test_pq_field_key_id_derives_from_the_public_key() -> None:
    signed, _, _ = _signed_packet()
    field = signed["packet_pq_signature"]
    pub = rqpq.pq_public_key_from_hex(field["public_key_hex"])
    assert field["key_id"] == rqpq.pq_key_id_from_public_key(pub)


def test_signature_decodes_to_bytes() -> None:
    signed, _, _ = _signed_packet()
    raw = base64.b64decode(signed["packet_pq_signature"]["signature_b64"], validate=True)
    assert len(raw) > 0


def test_signed_field_is_outside_digest_body() -> None:
    signed, _, _ = _signed_packet()
    body = dict(signed)
    body.pop("packet_content_sha256")
    body.pop("packet_pq_signature")
    stamp = packet.SHA256_PREFIX + hashlib.sha256(packet.canonical_json(body).encode()).hexdigest()
    assert signed["packet_content_sha256"] == stamp


def test_signing_same_key_same_digest_each_verifies() -> None:
    # ML-DSA signs with per-call randomised padding, so signatures differ
    # between runs; the digest both cover is identical and each verifies.
    pq_priv, _, _ = rqpq.pq_generate()
    a = packet.build_packet(DEMO_STORE, pq_private=pq_priv)
    b = packet.build_packet(DEMO_STORE, pq_private=pq_priv)
    assert a["packet_content_sha256"] == b["packet_content_sha256"]
    assert a["packet_pq_signature"]["signature_b64"] != b["packet_pq_signature"]["signature_b64"]
    assert rv._verify_pq_signature_field(a) is None
    assert rv._verify_pq_signature_field(b) is None


def test_cli_revalidator_reproduces_signed_packet(tmp_path: pathlib.Path) -> None:
    signed, _, _ = _signed_packet()
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(signed, indent=2, sort_keys=True) + "\n")
    assert rv.main(["--packet", str(packet_path), "--evidence-store", str(DEMO_STORE)]) == 0


def test_cli_revalidator_fails_on_tampered_body(tmp_path: pathlib.Path) -> None:
    signed, _, _ = _signed_packet()
    tampered = json.loads(json.dumps(signed))
    tampered["risk_annotations"] = ["tampered"]
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(tampered) + "\n")
    assert rv.main(["--packet", str(packet_path), "--evidence-store", str(DEMO_STORE)]) == 1


def test_verify_field_roundtrip_does_not_raise() -> None:
    signed, _, _ = _signed_packet()
    assert rv._verify_pq_signature_field(signed) is None


def test_verify_rejects_wrong_digest() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    bad["packet_content_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(rv._Fail, match="digest"):
        rv._verify_pq_signature_field(bad)


def test_verify_rejects_wrong_key_id() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    bad["packet_pq_signature"]["key_id"] = "0" * 16
    with pytest.raises(rv._Fail, match="key_id"):
        rv._verify_pq_signature_field(bad)


def test_verify_rejects_tampered_signature() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    field = bad["packet_pq_signature"]
    raw = bytearray(base64.b64decode(field["signature_b64"]))
    raw[0] ^= 0xFF
    field["signature_b64"] = base64.b64encode(bytes(raw)).decode()
    with pytest.raises(rv._Fail, match="ML-DSA"):
        rv._verify_pq_signature_field(bad)


def test_verify_rejects_wrong_algorithm() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    bad["packet_pq_signature"]["algorithm"] = "rsa-pss"
    with pytest.raises(rv._Fail, match="algorithm"):
        rv._verify_pq_signature_field(bad)


def test_verify_rejects_malformed_signature_b64() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    bad["packet_pq_signature"]["signature_b64"] = "!!! not base64 !!!"
    with pytest.raises(rv._Fail, match="base64"):
        rv._verify_pq_signature_field(bad)


def test_diff_excludes_pq_field() -> None:
    signed, _, _ = _signed_packet()
    stripped = dict(signed)
    stripped.pop("packet_pq_signature")
    rederived = rv.rederive_packet_from_inputs(DEMO_STORE)
    assert rv._diff(stripped, rederived) == []


def test_cli_pq_key_loader_missing_file_is_named_error() -> None:
    with pytest.raises(ValueError, match="not found"):
        packet._load_pq_private_key(str(REPO_ROOT / "no" / "such-key.pem"))


def test_cli_pq_key_loader_roundtrip(tmp_path: pathlib.Path) -> None:
    pq_priv, _, _ = rqpq.pq_generate()
    pem_path = tmp_path / "pq-key.pem"
    pem_path.write_text(rqpq.pq_private_key_pem(pq_priv))
    loaded = packet._load_pq_private_key(str(pem_path))
    roundtrip = packet.build_packet(DEMO_STORE, pq_private=loaded)
    signed, _, _ = _signed_packet()
    del signed
    assert roundtrip["packet_pq_signature"]["algorithm"] == "ml-dsa-65"
    assert rv._verify_pq_signature_field(roundtrip) is None


def test_verify_rejects_non_object_field() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    bad["packet_pq_signature"] = "not-an-object"
    with pytest.raises(rv._Fail, match="must be an object"):
        rv._verify_pq_signature_field(bad)


def test_verify_rejects_non_string_public_key_hex() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    bad["packet_pq_signature"]["public_key_hex"] = 42
    with pytest.raises(rv._Fail, match="public_key_hex"):
        rv._verify_pq_signature_field(bad)


def test_verify_rejects_public_key_hex_not_a_key() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    bad["packet_pq_signature"]["public_key_hex"] = "ab"
    with pytest.raises(rv._Fail, match="ML-DSA-65 key"):
        rv._verify_pq_signature_field(bad)


def test_verify_rejects_non_string_signature_b64() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    bad["packet_pq_signature"]["signature_b64"] = 7
    with pytest.raises(rv._Fail, match="base64"):
        rv._verify_pq_signature_field(bad)


def test_verify_rejects_non_string_stamp() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    bad["packet_content_sha256"] = 12345
    with pytest.raises(rv._Fail, match="digest string"):
        rv._verify_pq_signature_field(bad)


def test_verify_fails_closed_when_pq_backend_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed, _, _ = _signed_packet()
    monkeypatch.setattr(rv._rqpq, "pq_available", lambda: False)
    with pytest.raises(rv._Fail, match="cannot"):
        rv._verify_pq_signature_field(signed)


def test_verify_rejects_key_id_of_wrong_form() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    bad["packet_pq_signature"]["key_id"] = ""
    with pytest.raises(rv._Fail, match="16-char key id"):
        rv._verify_pq_signature_field(bad)


def test_verify_rejects_malformed_public_key_hex() -> None:
    signed, _, _ = _signed_packet()
    bad = json.loads(json.dumps(signed))
    bad["packet_pq_signature"]["public_key_hex"] = "zz zz"
    with pytest.raises(rv._Fail, match="is not hex"):
        rv._verify_pq_signature_field(bad)


def test_verify_fails_closed_when_raucle_module_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed, _, _ = _signed_packet()
    monkeypatch.setattr(rv, "_rqpq", None)
    with pytest.raises(rv._Fail, match="raucle"):
        rv._verify_pq_signature_field(signed)
