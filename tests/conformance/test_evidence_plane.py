# SPDX-License-Identifier: Apache-2.0
"""Raucle-free unit tests for the evidence-plane module (ADR-0001 semantics).

These tests require NO raucle install and NO signed-key environment: they
exercise EvidenceStore and TrustRootRegistry directly, plus rotation semantics
derived from the committed fixture corpus envelopes alone (JWS parsing only,
no signature verification). CI runs them on every push.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import pathlib

import pytest

from oaa_raucle_adapter.evidence_plane import (
    EvidenceStore,
    TrustRoot,
    TrustRootRegistry,
)

CORPUS = pathlib.Path(__file__).with_name("corpus.jsonl")


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _corpus_envelope(name: str) -> str:
    for rec in (json.loads(line) for line in CORPUS.read_text().splitlines()):
        if rec["name"] == name and not rec.get("simulated"):
            return rec["envelope"]
    raise LookupError(name)


# ---------------------------------------------------------------------------
# Envelope shape enforcement
# ---------------------------------------------------------------------------


def test_put_rejects_wrong_envelope_shape(tmp_path):
    store = EvidenceStore(tmp_path / "e.jsonl")
    for bad in ('{"receipt_hash": "sha256:x"}', '{"jws": "a.b.c"}', "{}"):
        with pytest.raises(ValueError, match="exactly"):
            store.put(bad)


def test_put_rejects_extra_envelope_fields(tmp_path):
    store = EvidenceStore(tmp_path / "e.jsonl")
    line = json.dumps(
        {
            "receipt_hash": "sha256:abc",
            "jws": "a.b.c",
            "status": "valid",
        }
    )
    with pytest.raises(ValueError, match="exactly"):
        store.put(line)


def test_corpus_envelopes_all_have_canonical_shape():
    """Every committed conformance envelope is exactly {receipt_hash, jws}."""
    for line in CORPUS.read_text().splitlines():
        rec = json.loads(line)
        if rec.get("simulated"):
            continue
        assert set(json.loads(rec["envelope"])) == {"receipt_hash", "jws"}


# ---------------------------------------------------------------------------
# Digest integrity / byte-verbatim storage
# ---------------------------------------------------------------------------


def test_store_roundtrip_is_byte_verbatim(tmp_path):
    envelope = _corpus_envelope("valid_allow")
    store = EvidenceStore(tmp_path / "e.jsonl")
    digest = store.put(envelope)
    assert store.get(_receipt_hash(envelope)) == envelope
    assert store.get_by_digest(digest) == envelope
    # raw file bytes are exactly the stored lines
    assert (tmp_path / "e.jsonl").read_text() == envelope + "\n"


def _receipt_hash(envelope: str) -> str:
    return json.loads(envelope)["receipt_hash"]


def test_get_by_digest_detects_byte_drift(tmp_path):
    store = EvidenceStore(tmp_path / "e.jsonl")
    digest = store.put(_corpus_envelope("valid_allow"))
    # mutate one byte on disk (simulating tampering of stored bytes)
    path = tmp_path / "e.jsonl"
    mutated = path.read_text().replace("sha256:", "sha255:", 1)
    assert mutated != path.read_text()
    path.write_text(mutated)
    with pytest.raises(FileNotFoundError, match="digest"):
        store.get_by_digest(digest)


def test_get_missing_receipt_hash_raises(tmp_path):
    store = EvidenceStore(tmp_path / "e.jsonl")
    store.put(_corpus_envelope("valid_allow"))
    with pytest.raises(FileNotFoundError, match="not in evidence store"):
        store.get("sha256:does-not-exist")


# ---------------------------------------------------------------------------
# Trust-root registry: event-time selection (ADR-0001 §2)
# ---------------------------------------------------------------------------

T0 = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)
T1 = dt.datetime(2026, 6, 1, tzinfo=dt.UTC)
T2 = dt.datetime(2026, 12, 1, tzinfo=dt.UTC)
PEM_A = "-----BEGIN PUBLIC KEY-----A-----END PUBLIC KEY-----"
PEM_B = "-----BEGIN PUBLIC KEY-----B-----END PUBLIC KEY-----"


def _reg_current() -> TrustRootRegistry:
    reg = TrustRootRegistry()
    reg.add(TrustRoot("kid-a", PEM_A, T0.isoformat(), None, "current"))
    return reg


def test_event_time_selection_window_boundaries():
    assert "kid-a" in _reg_current().keys_for_event_time(T1)
    # valid_from is inclusive
    assert "kid-a" in _reg_current().keys_for_event_time(T0)
    # after valid_until is excluded
    reg = TrustRootRegistry()
    reg.add(TrustRoot("kid-a", PEM_A, T0.isoformat(), T2.isoformat(), "current"))
    assert "kid-a" in reg.keys_for_event_time(T1)
    assert "kid-a" not in reg.keys_for_event_time(T2)  # valid_until exclusive
    # before valid_from is excluded
    assert "kid-a" not in reg.keys_for_event_time(T0 - dt.timedelta(seconds=1))


# ---------------------------------------------------------------------------
# Rotation semantics with the fixtures corpus only (no raucle)
# ---------------------------------------------------------------------------


def _kid_event_time(envelope: str) -> tuple[str, dt.datetime]:
    jws = json.loads(envelope)["jws"]
    kid = json.loads(_b64d(jws.split(".")[0]))["kid"]
    iat = json.loads(_b64d(jws.split(".")[1]))["iat"]
    return kid, dt.datetime.fromtimestamp(int(iat), tz=dt.UTC)


@pytest.fixture(scope="module")
def corpus_kid_event_time():
    kid, event_time = _kid_event_time(_corpus_envelope("valid_allow"))
    return kid, event_time, _corpus_envelope("valid_allow")


def test_rotation_retire_archives_never_deletes(corpus_kid_event_time):
    kid, event_time, _ = corpus_kid_event_time
    reg = TrustRootRegistry()
    reg.add(TrustRoot(kid, PEM_A, T0.isoformat(), None, "current"))
    reg.retire(kid, valid_until=(event_time + dt.timedelta(hours=1)).isoformat())
    # archived, not deleted: the root is still present and still selects at
    # the receipt's event time — historic verification never degrades.
    assert reg.knows(kid)
    assert [r.status for r in reg.roots] == ["retired"]
    assert kid in reg.keys_for_event_time(event_time)


def test_rotation_event_time_window_must_cover_the_event(corpus_kid_event_time):
    kid, event_time, _ = corpus_kid_event_time
    reg = TrustRootRegistry()
    reg.add(TrustRoot(kid, PEM_A, T0.isoformat(), None, "current"))
    # retire with a window that ENDS before the event: key not trusted at
    # event time, and registry.knows still reports it (archived).
    reg.retire(kid, valid_until=(event_time - dt.timedelta(hours=1)).isoformat())
    assert reg.knows(kid)
    assert kid not in reg.keys_for_event_time(event_time)
    reg.add(TrustRoot("kid-b", PEM_B, T0.isoformat(), None, "current"))
    assert reg.keys_for_event_time(event_time) == {"kid-b": PEM_B}


def test_unknown_key_is_registry_absence_not_invalidity(corpus_kid_event_time):
    """kid never in registry → knows() False; that must surface as unknown_key
    downstream, never silently 'invalid' (corpus fixture unknown_key_v2only)."""
    kid, event_time, envelope = corpus_kid_event_time
    reg = TrustRootRegistry()  # empty archive: counterfactual from EVD-02
    assert not reg.knows(kid)
    assert reg.keys_for_event_time(event_time) == {}
    # and the envelope still exists, untouched: the store keeps it verbatim,
    # the absence is in the trust root only.
    assert json.loads(envelope)["jws"].count(".") == 2


def test_corpus_kid_is_consistent_across_fixtures():
    """All genuine envelopes in the corpus share one kid + event-time domain."""
    kids = set()
    for line in CORPUS.read_text().splitlines():
        rec = json.loads(line)
        if rec.get("simulated"):
            continue
        kids.add(_kid_event_time(rec["envelope"])[0])
    assert len(kids) == 1


def test_retire_unknown_key_id_raises():
    with pytest.raises(KeyError, match="no current trust root"):
        _reg_current().retire("kid-missing", valid_until=T2.isoformat())
