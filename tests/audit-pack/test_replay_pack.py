# SPDX-License-Identifier: Apache-2.0
"""P1.1b slice: per-decision replay rendered from the audit pack.

The pack built by the AUD-01 builder (real Ed25519 envelopes, pinned
key snapshot, chain graphs resolved via the OSS home) must replay one
receipt: decision summary, policy binding, per-hop scope, the honest
no-proof state, and a verified timestamp chain. The pending-graph pack
(the no-OSS-home build) must degrade honestly, never fabricate.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "services" / "investigation-ui" / "demo_data"
RAUCLE_OSS_HOME = pathlib.Path(os.environ.get("RAUCLE_OSS_HOME", "~/Projects/raucle")).expanduser()
CLOCK = dt.datetime(2026, 11, 5, 12, 0, 0, tzinfo=dt.UTC)

_spec = importlib.util.spec_from_file_location(
    "oaa_pack_replay",
    REPO_ROOT / "packages" / "raucle-adapter" / "src" / "oaa_raucle_adapter" / "replay.py",
)
assert _spec
assert _spec.loader
replay = importlib.util.module_from_spec(_spec)
sys.modules["oaa_pack_replay"] = replay
_spec.loader.exec_module(replay)


@pytest.fixture(scope="module")
def pack_dirs(tmp_path_factory) -> dict[str, pathlib.Path]:
    """One graph-resolved pack and one pending-graph pack (honest slot)."""
    from test_audit_pack import pack  # noqa: PLC0415 - AUD-01 builder by path

    root = tmp_path_factory.mktemp("replay-pack")
    os.environ["RAUCLE_OSS_HOME"] = str(RAUCLE_OSS_HOME)
    resolved = pack.build_pack(
        DEMO / "evidence_store.jsonl",
        DEMO / "trust_roots.jsonl",
        root / "resolved",
        clock=CLOCK,
    )["pack_dir"]
    os.environ.pop("RAUCLE_OSS_HOME", None)
    pending = pack.build_pack(
        DEMO / "evidence_store.jsonl",
        DEMO / "trust_roots.jsonl",
        root / "pending",
        clock=CLOCK,
    )["pack_dir"]
    return {"resolved": pathlib.Path(resolved), "pending": pathlib.Path(pending)}


def _first_receipt_hash(pack_dir: pathlib.Path) -> str:
    lines = (pack_dir / "receipts.jsonl").read_text().splitlines()
    return json.loads(next(ln for ln in lines if ln.strip()))["receipt_hash"]


def _replay(pack_dir: pathlib.Path) -> dict:
    return replay.replay_receipt_from_pack(pack_dir, _first_receipt_hash(pack_dir))


@pytest.mark.skipif(
    not RAUCLE_OSS_HOME.is_dir(),
    reason="chain-graph resolver unavailable without the OSS raucle tree (pack degrades to the pending slot)",
)
def test_replay_renders_the_decision_and_the_chain(pack_dirs) -> None:
    body = _replay(pack_dirs["resolved"])
    receipt_hash = _first_receipt_hash(pack_dirs["resolved"])
    assert body["receipt_hash"] == receipt_hash
    assert body["decision"]["state"] == "resolved"
    assert body["decision"]["decision"] in ("allow", "deny", "unknown")
    assert body["decision"]["signature_state"] is not None
    chain = body["authority_chain"]
    nodes = chain["nodes"]
    assert nodes
    assert all("signature" in node for node in nodes)


def test_replay_policy_is_honest_about_versioned_text(pack_dirs) -> None:
    for pack_dir in pack_dirs.values():
        policy = _replay(pack_dir)["policy"]
        assert policy["binding_state"] in (
            "deployment_bound",
            "receipt_rule_digest_only",
            "unbound",
        )
        if policy["version_in_force"] is None:
            assert policy["version_null_reason"]
        assert isinstance(policy["policy_files_in_pack"], list)


def test_replay_proofs_are_never_faked(pack_dirs) -> None:
    for pack_dir in pack_dirs.values():
        for proof in _replay(pack_dir)["proofs"]:
            assert proof["state"] == "no_proof_recorded"
            assert proof["detail"]


def test_replay_hops_state_the_pack_gap_honestly(pack_dirs) -> None:
    for pack_dir in pack_dirs.values():
        for hop in _replay(pack_dir)["hops"]:
            if hop.get("state") == "unresolved":
                assert hop["honest_note"]
            else:
                assert "constraints" in hop
                assert hop["proof"]["state"] == "no_proof_recorded"


def test_replay_verify_uses_the_pinned_snapshot(pack_dirs) -> None:
    for pack_dir in pack_dirs.values():
        rows = _replay(pack_dir)["verify"]
        assert rows
        assert rows[0]["receipt_hash"] == _first_receipt_hash(pack_dir)
        assert rows[0]["verify"] in ("valid", "invalid", "unknown_key", "unreachable")


def test_replay_timestamps_are_recorded_and_ordered(pack_dirs) -> None:
    for pack_dir in pack_dirs.values():
        stamps = _replay(pack_dir)["timestamps"]
        assert stamps
        assert any(s["kind"] == "receipt" for s in stamps)
        ats = [s["at"] for s in stamps]
        assert ats == sorted(ats)


def test_replay_pending_graph_degrades_honestly(pack_dirs) -> None:
    """No resolved graph: the replay says so and still verifies the bytes."""
    body = _replay(pack_dirs["pending"])
    assert body["decision"]["state"] == "graph_absent"
    assert body["authority_chain"]["graph_status"] == "pending P1.1a wire-up"
    assert body["authority_chain"]["nodes"] == []
    verdict = body["decision"]["decision"]
    assert verdict in ("allow", "deny"), "the envelope payload itself is shown"
    assert body["verify"]
    assert body["verify"][0]["verify"] == "valid"


def test_replay_unknown_receipt_raises(pack_dirs) -> None:
    with pytest.raises(LookupError):
        replay.replay_receipt_from_pack(pack_dirs["resolved"], "sha256:" + "0" * 64)
