"""BUG-HUNT round 2: malformed evidence-store lines must fail named in epaec.

Round-2 fuzzing of the EP-AEC generator found raw JSONDecodeError /
AttributeError / binascii leaks on malformed JSONL store lines and malformed
JWS receipts, instead of named ValueErrors carrying the file context.
"""

import base64
import json

import pytest

from oaa_epaec.generator import _payload_of, read_evidence_store


def _store(tmp_path, lines):
    # read_evidence_store scans a store DIRECTORY for *.jsonl files.
    store_dir = tmp_path / "store"
    store_dir.mkdir(exist_ok=True)
    p = store_dir / "store.jsonl"
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return p


def _write(tmp_path, lines):
    return _store(tmp_path, lines).parent


def b64u(b):
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def test_read_store_non_mapping_line_is_named(tmp_path):
    p = _write(tmp_path, ['["receipt_hash", "jws"]'])
    with pytest.raises(ValueError) as exc:
        read_evidence_store(p)
    assert "store.jsonl" in str(exc.value)


def test_read_store_unparsable_line_is_named(tmp_path):
    p = _write(tmp_path, ["{not json"])
    with pytest.raises(ValueError) as exc:
        read_evidence_store(p)
    assert "store.jsonl" in str(exc.value)


def test_read_store_non_string_jws_is_named(tmp_path):
    p = _write(tmp_path, ['{"receipt_hash": "sha256:x", "jws": 42}'])
    with pytest.raises(ValueError) as exc:
        read_evidence_store(p)
    assert "store.jsonl" in str(exc.value)


def test_payload_of_malformed_jws_is_named():
    for jws in ["nodots", "a.b", "aaaa.", ".payload.sig"]:
        with pytest.raises(ValueError) as exc:
            _payload_of({"jws": jws})
        assert "malformed receipt JWS" in str(exc.value)


def test_payload_of_unparsable_payload_is_named():
    with pytest.raises(ValueError) as exc:
        _payload_of({"jws": f"{b64u(b'{}')}.{b64u(b'not json')}.{b64u(b'sig')}"})
    assert "malformed receipt JWS" in str(exc.value)


def test_payload_of_valid_payload_ok():
    payload = json.dumps({"a": 1}).encode()
    out = _payload_of({"jws": f"{b64u(b'{}')}.{b64u(payload)}.{b64u(b'sig')}"})
    assert out == {"a": 1}
