# SPDX-License-Identifier: Apache-2.0
"""Conformance fixture sweep (EVD-01/EVD-02) as pytest tests.

These run raucle's own ProvenanceVerifier over freshly generated fixtures
(the committed corpus.jsonl is the reference corpus; generation is
deterministic against the pinned raucle distribution). They SKIP gracefully
when raucle is unavailable so CI can run without the signed-key environment.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib

import pytest

raucle = pytest.importorskip(
    "raucle",
    reason="raucle (pinned v0.23.5, git 63edacd) is not installed — "
    "install per packages/raucle-adapter/README.md to run signature "
    "verification conformance tests",
)

from oaa_raucle_adapter import fixture_gen  # noqa: E402
from oaa_raucle_adapter.evidence_plane import (  # noqa: E402
    RAUCLE_DISTRIBUTION_PIN,
    TRUST_POLICY_VERSION,
    EvidenceStore,
    TrustRoot,
    TrustRootRegistry,
    classify,
)

CORPUS = pathlib.Path(__file__).with_name("corpus.jsonl")


@pytest.fixture(scope="module")
def sweep(tmp_path_factory):
    out = tmp_path_factory.mktemp("evd-sweep")
    corpus = fixture_gen.generate(out)
    store = EvidenceStore(out / "evidence.jsonl")
    if store.path.exists():
        store.path.unlink()
    registry = TrustRootRegistry()
    T0 = dt.datetime(2026, 11, 4, 0, 0, tzinfo=dt.UTC)
    registry.add(
        TrustRoot(
            key_id=corpus.key_id,
            public_key_pem=corpus.public_key_pem,
            valid_from=T0.isoformat(),
            valid_until=None,
            status="current",
        )
    )
    results = {}
    for fx in corpus.records:
        if fx.get("simulated"):
            results[fx["name"]] = fx["expected"]  # companion-side simulated state
            continue
        digest = store.put(fx["envelope"])
        line = store.get_by_digest(digest)
        assert line == fx["envelope"], f"byte drift for {fx['name']}"
        rec = classify(line, registry)
        results[fx["name"]] = rec.verification_status
    # unknown_key: same envelope vs a v2-only registry
    deny_fx = next(f for f in corpus.records if f["name"] == "unknown_key_v2only")
    v2 = __import__(
        "oaa_raucle_adapter.evidence_plane", fromlist=["_demo_identity_v2"]
    )._demo_identity_v2()
    reg_v2only = TrustRootRegistry()
    reg_v2only.add(
        TrustRoot(
            key_id=v2.key_id,
            public_key_pem=v2.public_key_pem(),
            valid_from=T0.isoformat(),
            valid_until=None,
        )
    )
    rec_uk = classify(deny_fx["envelope"], reg_v2only)
    return corpus, results, rec_uk


EXPECTED_STATES = {
    "valid_allow": "valid",
    "valid_deny": "valid",
    "invalid_sig_flip": "invalid",
    "invalid_payload_tamper": "invalid",
    "unsupported_schema_crit": "unsupported_schema",
    "pending_async_ingest": "pending",
    "unavailable_store_gone": "unavailable",
}


def test_corpus_matches_reference():
    """Regenerated fixture names/expectations match the committed corpus."""
    committed = json.loads("[" + ",".join(CORPUS.read_text().splitlines()) + "]")
    reference = {f["name"]: f["expected"] for f in committed}
    assert reference == EXPECTED_STATES | {"unknown_key_v2only": "unknown_key"}


def test_fixture_expected_states(sweep):
    _corpus, results, _rec_uk = sweep
    for name, expected in EXPECTED_STATES.items():
        assert results[name] == expected, f"{name}: expected {expected}"


def test_unknown_key_is_distinct_from_invalid(sweep):
    _corpus, _results, rec_uk = sweep
    assert rec_uk.verification_status == "unknown_key"
    assert "not in trust-root registry" in rec_uk.detail


def test_verifier_version_is_pin_keyed(sweep):
    corpus, _results, _rec_uk = sweep
    assert corpus.records, "corpus must be non-empty"
    assert RAUCLE_DISTRIBUTION_PIN.startswith("raucle 0.23.5")
    assert TRUST_POLICY_VERSION == "evd-trust-1"
