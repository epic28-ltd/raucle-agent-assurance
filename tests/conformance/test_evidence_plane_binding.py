# SPDX-License-Identifier: Apache-2.0
"""Evidence-plane binding: happy path and honest mismatch paths.

The classify() state machine must never infer valid from absence: an
unknown signing key is unknown_key (a registry absence), a key known but
not trusted at event time is invalid, a tampered receipt_hash is invalid
before any crypto runs, a schema-family error is unsupported_schema, and
everything else raucle rejects is invalid. raucle is the optional
dependency here: its verifier is stubbed at module boundary with a
real-Ed25519 minted envelope, mapping raucle outcomes to ADR-0001 states.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import pathlib
import sys
import types

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from oaa_raucle_adapter import evidence_plane
from oaa_raucle_adapter.evidence_plane import (
    RAUCLE_DISTRIBUTION_PIN,
    TRUST_POLICY_VERSION,
    EvidenceStore,
    TrustRoot,
    TrustRootRegistry,
    VerificationResult,
    classify,
)

KID = "0123456789abcdef"


def _mint(kid: str = KID, iat: int | None = None) -> tuple[dict, str]:
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
    iat = iat if iat is not None else int(dt.datetime(2026, 11, 5, 12, tzinfo=dt.UTC).timestamp())
    hp = (
        base64.urlsafe_b64encode(
            json.dumps({"alg": "EdDSA", "kid": kid, "typ": "provenance-receipt/v1"}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    pp = (
        base64.urlsafe_b64encode(
            json.dumps({"agent_id": "agent:x", "iat": iat}, separators=(",", ":")).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    sig = base64.urlsafe_b64encode(key.sign(f"{hp}.{pp}".encode())).rstrip(b"=").decode()
    jws = f"{hp}.{pp}.{sig}"
    line = json.dumps(
        {"receipt_hash": "sha256:" + hashlib.sha256(jws.encode()).hexdigest(), "jws": jws}
    )
    return row, line


class _StubReport:
    def __init__(self, valid: bool, errors: list[str]):
        self.valid = valid
        self._errors = errors

    def to_dict(self):
        return {"valid": self.valid, "errors": self._errors}


@pytest.fixture
def stub_raucle(monkeypatch: pytest.MonkeyPatch):
    """A raucle module boundary stub whose verify_chain returns a set outcome."""
    outcome = {"valid": True, "errors": []}

    class ProvenanceVerifier:
        def __init__(self, public_keys):
            ProvenanceVerifier.seen_keys = public_keys
            assert public_keys, "registry must hand PEM bytes to the verifier"

        def verify_chain(self, _path):
            return _StubReport(outcome["valid"], outcome["errors"])

    mod = types.ModuleType("raucle")
    prov = types.ModuleType("raucle.provenance")
    gw = types.ModuleType("raucle.gateway")
    prov.ProvenanceVerifier = ProvenanceVerifier
    mod.provenance = prov
    monkeypatch.setitem(sys.modules, "raucle", mod)
    monkeypatch.setitem(sys.modules, "raucle.provenance", prov)
    monkeypatch.setitem(sys.modules, "raucle.gateway", gw)
    return outcome


def _registry(row: dict) -> TrustRootRegistry:
    reg = TrustRootRegistry()
    reg.add(TrustRoot(row["key_id"], row["public_key_pem"], row["valid_from"], row["valid_until"]))
    return reg


def test_binding_happy_path_is_valid(stub_raucle) -> None:
    row, line = _mint()
    out = classify(line, _registry(row))
    assert out.verification_status == "valid"
    assert out.verifier_version == RAUCLE_DISTRIBUTION_PIN
    assert out.trust_policy_version == TRUST_POLICY_VERSION
    assert any(c.startswith("jose_header_parsed") for c in out.checks_performed)
    assert any(c.startswith("event_time") for c in out.checks_performed)


def test_receipt_without_trusted_registry_is_unknown_key(stub_raucle) -> None:
    """A key the archive does not carry is unknown_key — registry absence,
    never silently folded into invalid."""
    _row, line = _mint(kid="absent-key")
    reg = TrustRootRegistry()  # knows no keys at all
    out = classify(line, reg)
    assert out.verification_status == "unknown_key"
    assert "absent from archive" in " ".join(out.checks_performed)


def test_key_known_but_not_trusted_at_event_time_is_invalid(stub_raucle) -> None:
    row, line = _mint()
    # the key exists in the archive but only became valid after the event
    reg = TrustRootRegistry()
    reg.add(TrustRoot(row["key_id"], row["public_key_pem"], "2099-01-01T00:00:00+00:00", None))
    out = classify(line, reg)
    assert out.verification_status == "invalid"
    assert "not trusted at event time" in " ".join(out.checks_performed)


def test_tampered_receipt_hash_is_invalid(stub_raucle) -> None:
    _row, line = _mint()
    rec = json.loads(line)
    rec["receipt_hash"] = "sha256:" + "ab" * 32
    out = classify(json.dumps(rec), _registry(_mint()[0]))
    assert out.verification_status == "invalid"
    assert any("receipt_hash mismatch" in c for c in out.checks_performed)


def test_signature_failure_is_invalid(stub_raucle) -> None:
    stub_raucle.update(valid=False, errors=["signature verification failed"])
    row, line = _mint()
    out = classify(line, _registry(row))
    assert out.verification_status == "invalid"
    assert "signature verification failed" in out.detail


def test_unsupported_schema_error_is_its_own_state(stub_raucle) -> None:
    stub_raucle.update(valid=False, errors=["unknown critical header parameter 'hoge'"])
    row, line = _mint()
    out = classify(line, _registry(row))
    assert out.verification_status == "unsupported_schema"


def test_generic_verifier_failure_degrades_to_invalid_not_valid(stub_raucle) -> None:
    stub_raucle.update(valid=False, errors=["chain reconstruction failed"])
    row, line = _mint()
    out = classify(line, _registry(row))
    assert out.verification_status == "invalid"


def test_result_record_roundtrips(stub_raucle) -> None:
    row, line = _mint()
    out = classify(line, _registry(row))
    d = out.to_dict()
    assert d["verification_status"] == "valid"
    assert isinstance(out, VerificationResult)


def test_missing_raucle_raises_with_install_guidance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """raucle is optional: without it the plane raises ImportError with
    install guidance, it does not fall back to an unverified state."""

    class _Blocker:
        def find_spec(self, name, path=None, target=None):
            if name == "raucle" or name.startswith("raucle."):
                raise ImportError("raucle blocked for this test")
            return None

    monkeypatch.setattr(sys, "meta_path", [_Blocker()])
    with pytest.raises(ImportError, match="raucle is required"):
        evidence_plane._raucle()


# ------------------------------------------------ store / registry edges ----


def test_store_get_returns_first_verbatim_line(tmp_path: pathlib.Path):
    store = EvidenceStore(tmp_path / "e.jsonl")
    _row, line = _mint()
    digest = store.put(line)
    _row2, line2 = _mint()
    store.put(line2)
    first = store.get(json.loads(line)["receipt_hash"])
    assert first == line
    assert (
        json.loads(store.get_by_digest(digest))["receipt_hash"] == json.loads(line)["receipt_hash"]
    )


def test_store_get_missing_hash_raises(tmp_path: pathlib.Path):
    store = EvidenceStore(tmp_path / "e.jsonl")
    with pytest.raises(FileNotFoundError):
        store.get("sha256:" + "ff" * 32)


def test_registry_knows_and_roots_snapshot():
    reg = TrustRootRegistry()
    reg.add(TrustRoot(KID, "pem", "1970-01-01T00:00:00+00:00", None))
    assert reg.knows(KID) and not reg.knows("other")
    assert [r.key_id for r in reg.roots] == [KID]
