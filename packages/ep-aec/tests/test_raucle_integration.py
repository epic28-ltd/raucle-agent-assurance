# SPDX-License-Identifier: Apache-2.0
"""raucle-optional integration: classify REAL raucle-minted fixtures through
oaa-raucle-adapter.evidence_plane and generate VERIFIED AEC components.

Skipped (with a reason) whenever raucle is not importable in this env —
raucle is an OPTIONAL pinned dependency (raucle 0.23.5, git 63edacd).
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json

import pytest
from helpers import gate_payload, make_store

from oaa_epaec import EpaecConfig, build_envelope
from oaa_epaec.objects import SATISFIED, trust_snapshot_digest

FROZEN = dt.datetime(2026, 11, 4, 12, 0, 0, tzinfo=dt.UTC)

raucle_spec = importlib.util.find_spec("raucle")
pytestmark = pytest.mark.skipif(
    raucle_spec is None, reason="raucle not installed (optional pinned dependency)"
)


@pytest.fixture(scope="module")
def real_store(tmp_path_factory):
    """Mint genuine receipts via raucle's own signing path and snapshot the
    valid envelopes into a {receipt_hash, jws} store directory."""
    from oaa_raucle_adapter import fixture_gen
    from oaa_raucle_adapter.evidence_plane import TrustRoot, TrustRootRegistry

    out = tmp_path_factory.mktemp("raucle-corpus")
    corpus = fixture_gen.generate(out)
    valid = [r for r in corpus.records if r.get("expected") == "valid"]
    if not valid:
        pytest.skip("fixture corpus produced no valid receipts")
    store_dir = out / "ep-store"
    store_dir.mkdir()
    hashes: list[str] = []
    with open(store_dir / "store.jsonl", "wb") as fh:
        for r in valid:
            rec = json.loads(r["envelope"])
            hashes.append(rec["receipt_hash"])
            fh.write(r["envelope"].encode() + b"\n")
    root = TrustRoot(
        key_id=corpus.key_id,
        public_key_pem=corpus.public_key_pem,
        valid_from="2020-01-01T00:00:00+00:00",
        valid_until=None,
    )
    registry = TrustRootRegistry()
    registry.add(root)
    return store_dir, hashes, registry


def _line(store_dir, receipt_hash) -> str:
    for ln in (store_dir / "store.jsonl").read_bytes().splitlines():
        if json.loads(ln)["receipt_hash"] == receipt_hash:
            return ln.decode()
    raise AssertionError(receipt_hash)


def test_real_classify_drives_verified_components(real_store):
    from oaa_raucle_adapter.evidence_plane import classify

    store_dir, hashes, registry = real_store
    ground = [classify(_line(store_dir, h), registry) for h in hashes]
    assert all(g.verification_status == "valid" for g in ground)

    env = build_envelope(store_dir, hashes, registry=registry, now=FROZEN)
    assert env["replay"]["verdict"] == SATISFIED
    for comp in env["replay"]["components"]:
        assert comp["result"] == "VERIFIED"
        assert comp["verification_status"] == "valid"
        assert comp["verifier_version"]  # raucle distro pin recorded
        assert comp["trust_snapshot_digest"].startswith("sha256:")
        assert comp["status_checks"], "per-component checklist recorded"
    assert env["replay"]["components"][0]["trust_snapshot_digest"] == trust_snapshot_digest(
        [
            {
                "key_id": registry.roots[0].key_id,
                "valid_from": registry.roots[0].valid_from,
                "valid_until": registry.roots[0].valid_until,
                "status": registry.roots[0].status,
            }
        ]
    )
    for comp in env["replay"]["components"]:
        assert "jws" not in comp["evidence"]
        assert set(comp["evidence"]) <= {
            "receipt_hash",
            "verification_status",
            "verifier_version",
            "trust_policy_version",
        }


def test_unknown_key_registry_yields_accepted_not_verified(real_store):
    from oaa_raucle_adapter.evidence_plane import TrustRoot, TrustRootRegistry

    store_dir, hashes, _ = real_store
    stranger = TrustRootRegistry()
    stranger.add(
        TrustRoot(
            key_id="someone-else",
            public_key_pem="-----BEGIN PUBLIC KEY-----\nnone\n-----END PUBLIC KEY-----",
            valid_from="2020-01-01T00:00:00+00:00",
            valid_until=None,
        )
    )
    env = build_envelope(
        store_dir,
        hashes[:1],
        registry=stranger,
        config=EpaecConfig(component_type="policy-permit"),
        now=FROZEN,
    )
    comp = env["replay"]["components"][0]
    assert comp["result"] == "ACCEPTED"
    assert comp["verification_status"] == "unknown_key"
    assert env["replay"]["verdict"] == SATISFIED  # role present; trust is the RP's job


def test_supplied_classification_matches_integrated_shape(tmp_path):
    """The caller-supplied classification path shapes the same record."""
    hashes = make_store(tmp_path / "s", [gate_payload()])
    env = build_envelope(
        tmp_path / "s",
        hashes,
        classifications={
            hashes[0]: {
                "verification_status": "valid",
                "verifier_version": "raucle 0.23.5 (git 63edacd)",
                "trust_policy_version": "evd-trust-1",
                "checked_at": "2026-11-04T12:00:00+00:00",
                "checks_performed": ["jose_header_parsed"],
            }
        },
        now=FROZEN,
    )
    comp = env["replay"]["components"][0]
    assert comp["result"] == "VERIFIED"
    assert comp["native_verifier_profile_digest"] == "oaa-raucle-verifier:0.23.5:63edacd"
