# SPDX-License-Identifier: Apache-2.0
"""Generator tests: store indexing, component evidence hygiene (no raw JWS),
SATISFIED/UNSATISFIED envelopes, injected-clock determinism."""

from __future__ import annotations

import datetime as dt
import json

import pytest
from helpers import gate_payload, make_store

from oaa_epaec import EpaecConfig, build_envelope, read_evidence_store
from oaa_epaec.objects import SATISFIED, UNSATISFIED, jcs

FROZEN = dt.datetime(2026, 11, 4, 12, 0, 0, tzinfo=dt.UTC)


@pytest.fixture()
def store(tmp_path):
    payloads = [gate_payload(trace_id=f"tr-{i}") for i in (1, 2)]
    hashes = make_store(tmp_path / "store", payloads)
    return tmp_path / "store", hashes


class TestStoreIndex:
    def test_read_store(self, store):
        store_dir, hashes = store
        index = read_evidence_store(store_dir)
        assert set(index) == set(hashes)
        assert all(e["hash_ok"] for e in index.values())

    def test_missing_receipt(self, store):
        store_dir, hashes = store
        with pytest.raises(FileNotFoundError):
            build_envelope(store_dir, [hashes[0], "sha256:" + "ff" * 32], now=FROZEN)


class TestEvidenceHygiene:
    def test_raw_jws_never_embedded_by_default(self, store):
        store_dir, hashes = store
        env = build_envelope(store_dir, hashes[:1], now=FROZEN)
        text = jcs(env)
        assert "jws" not in text
        for comp in env["aec"]["components"]:
            assert set(comp["evidence"]) <= {
                "receipt_hash",
                "verification_status",
                "verifier_version",
                "trust_policy_version",
            }
            assert comp["evidence_digest"] == comp["evidence"]["receipt_hash"]

    def test_embedding_requires_explicit_opt_in(self, store):
        store_dir, hashes = store
        env = build_envelope(
            store_dir,
            hashes[:1],
            config=EpaecConfig(allow_embed_jws=True),
            now=FROZEN,
        )
        assert env["aec"]["components"][0]["evidence"]["jws"]
        # the digest binds only to the embedding-free form being reproducible;
        # embedding is an operator decision recorded in the envelope itself.


class TestVerdicts:
    def test_satisfied_default_requirement(self, store):
        store_dir, hashes = store
        env = build_envelope(store_dir, hashes[:1], now=FROZEN)
        assert env["replay"]["verdict"] == SATISFIED
        assert env["aec"]["requirement"] == "policy-permit"

    def test_unsatisfied_unknown_requirement(self, store):
        store_dir, hashes = store
        env = build_envelope(store_dir, hashes[:1], requirement="custody-audit", now=FROZEN)
        assert env["replay"]["verdict"] == UNSATISFIED
        assert env["replay"]["reason_codes"] == [
            "EVAL_UNSATISFIED_ATOM:custody-audit",
            "EVAL_UNSATISFIED",
        ]

    def test_disallowed_requirement_is_rejection_not_unsatisfied(self, store):
        store_dir, hashes = store
        with pytest.raises(Exception, match="EVAL_"):
            build_envelope(store_dir, hashes[:1], requirement="(" * 50, now=FROZEN)

    def test_custom_gate_decision_role(self, store):
        store_dir, hashes = store
        env = build_envelope(
            store_dir,
            hashes[:1],
            config=EpaecConfig(component_type="rau-cle-gate-decision"),
            now=FROZEN,
        )
        assert env["aec"]["components"][0]["type"] == "rau-cle-gate-decision"
        assert env["replay"]["verdict"] == SATISFIED

    def test_requirement_over_multiple_components(self, store):
        store_dir, hashes = store
        env = build_envelope(
            store_dir,
            hashes,
            requirement="policy-permit AND policy-permit",
            now=FROZEN,
        )
        assert len(env["aec"]["components"]) == 2
        assert env["replay"]["verdict"] == SATISFIED


class TestDeterminism:
    def test_two_generations_byte_identical(self, store):
        store_dir, hashes = store
        e1 = build_envelope(store_dir, hashes[:1], now=FROZEN)
        e2 = build_envelope(store_dir, hashes[:1], now=FROZEN)
        assert jcs(e1) == jcs(e2)
        assert e1["envelope_digest"] == e2["envelope_digest"]

    def test_clock_leaks_change_the_record(self, store):
        store_dir, hashes = store
        e1 = build_envelope(store_dir, hashes[:1], now=FROZEN)
        e2 = build_envelope(store_dir, hashes[:1], now=FROZEN + dt.timedelta(seconds=1))
        assert e1["replay"]["evaluated_at"] != e2["replay"]["evaluated_at"]
        # AEC itself is time-free; only the replay record carries the clock.
        assert jcs(e1["aec"]) == jcs(e2["aec"])

    def test_json_roundtrip_is_byte_stable(self, store):
        store_dir, hashes = store
        env = build_envelope(store_dir, hashes[:1], now=FROZEN)
        text = jcs(env)
        assert jcs(json.loads(text)) == text  # key order + numbers canonical
