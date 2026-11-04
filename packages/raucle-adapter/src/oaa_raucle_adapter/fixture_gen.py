# SPDX-License-Identifier: Apache-2.0
"""EVD-01 fixture-corpus generator — deterministic conformance fixtures.

Adapted from the EVD spike harness (`make_fixtures.py`). Generates a corpus of
gate-receipt envelopes covering every ADR-0001 verification state, minted by
raucle's own real signing path (never hand-constructed), plus a sanity pass
that every genuine envelope verifies under its own trust root before freezing.

Deterministic per run against the pinned raucle distribution. raucle is
imported lazily; see the package README for the v0.23.5 pin (git 63edacd).
"""

from __future__ import annotations

import base64
import json
import pathlib
import shutil
from dataclasses import dataclass

from oaa_raucle_adapter.evidence_plane import RAUCLE_DISTRIBUTION_PIN, _raucle

DEFAULT_POLICIES = """
version: 1
issuer: evd.demo
policies:
  - tool: read_file
    agent_id: agent:evd
    ttl_seconds: 300
    constraints:
      allow:
        path: ["/tmp/evd-allow.txt"]
  - tool: write_file
    agent_id: agent:evd
    ttl_seconds: 300
    constraints:
      allow:
        path: ["/tmp/evd-only.txt"]
"""


@dataclass
class FixtureCorpus:
    """Result of one deterministic fixture-generation run."""

    workspace: pathlib.Path
    records: list[dict]
    key_id: str
    public_key_pem: str

    @property
    def corpus_path(self) -> pathlib.Path:
        return self.workspace / "corpus.jsonl"


def new_gateway(workspace: pathlib.Path, name: str):
    RaucleGateway = _raucle().gateway.RaucleGateway
    GatewayConfig = _raucle().gateway.GatewayConfig
    policy_path = workspace / "policies.yaml"
    policy_path.write_text(DEFAULT_POLICIES)
    cfg = GatewayConfig(
        host="127.0.0.1",
        admin_api_key="k",
        signer_backend="local",
        policy_file=str(policy_path),
        receipt_store=str(workspace / f"{name}-receipts.jsonl"),
        audit_chain=str(workspace / f"{name}-audit.jsonl"),
        registry_path=str(workspace / f"{name}-registry.jsonl"),
        emit_receipts=True,
    )
    return cfg, RaucleGateway(cfg)


def capture_verbatim(cfg, receipt_ids: set[str]) -> dict[str, bytes]:
    """Read exact envelope lines from the raucle receipt store."""
    out: dict[str, bytes] = {}
    for line in open(cfg.receipt_store, "rb"):
        line = line.rstrip(b"\n")
        rec = json.loads(line)
        if rec["receipt_hash"] in receipt_ids:
            out[rec["receipt_hash"]] = line
    assert len(out) == len(receipt_ids), out.keys()
    return out


def b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def generate(workspace: pathlib.Path) -> FixtureCorpus:
    """Build the fixture corpus in *workspace* and write corpus.jsonl."""
    workspace = pathlib.Path(workspace)
    RaucleGateway = _raucle().gateway.RaucleGateway  # ensure lazy import path is valid
    assert RaucleGateway is not None
    workspace.mkdir(parents=True, exist_ok=True)
    if (workspace / "work").exists():
        shutil.rmtree(workspace / "work")
    work = workspace / "work"
    work.mkdir()

    ProvenanceVerifier = _raucle().provenance.ProvenanceVerifier  # noqa: F841 (sanity pass below)

    records: list[dict] = []
    cfg1, gw1 = new_gateway(workspace, "v1")
    kid_v1 = gw1.gate_identity.key_id

    # ---------------------------------------------------------------- valid
    r_allow = gw1.check_tool_call(
        "read_file",
        {"path": "/tmp/evd-allow.txt"},
        agent_id="agent:evd",
        source="agent",
        destination="fs",
        trace_id="evd-trace-0001",
    )
    r_deny = gw1.check_tool_call(
        "write_file",
        {"path": "/etc/passwd"},
        agent_id="agent:evd",
        source="agent",
        destination="fs",
        trace_id="evd-trace-0001",
    )
    env = capture_verbatim(cfg1, {r_allow["receipt_id"], r_deny["receipt_id"]})
    records.append(
        {
            "name": "valid_allow",
            "expected": "valid",
            "envelope": env[r_allow["receipt_id"]].decode(),
            "note": f"verbatim store envelope; gateway decision={r_allow['decision']!r}",
        }
    )
    records.append(
        {
            "name": "valid_deny",
            "expected": "valid",
            "envelope": env[r_deny["receipt_id"]].decode(),
            "note": f"verbatim store envelope; gateway decision={r_deny['decision']!r}",
        }
    )

    # ------------------------------------------------------ invalid variants
    tampered = json.loads(env[r_allow["receipt_id"]].decode())
    h, p, s = tampered["jws"].split(".")
    flip = ("A" if s[0] != "A" else "B") + s[1:]
    records.append(
        {
            "name": "invalid_sig_flip",
            "expected": "invalid",
            "envelope": json.dumps(
                {"receipt_hash": tampered["receipt_hash"], "jws": f"{h}.{p}.{flip}"},
                sort_keys=True,
                separators=(",", ": "),
            ),
            "note": "controlled copy: first char of signature segment flipped; "
            "verify_chain fails (signature + hash mismatch)",
        }
    )

    rec_deny = json.loads(env[r_deny["receipt_id"]].decode())
    h2, p2, s2 = rec_deny["jws"].split(".")
    pd = json.loads(b64d(p2))
    pd["x_gate"]["tool"] = "read_file"  # lie about the tool inside the signed payload
    new_deny_jws = (
        f"{h2}.{b64e(json.dumps(pd, separators=(',', ':'), sort_keys=True).encode())}.{s2}"
    )
    records.append(
        {
            "name": "invalid_payload_tamper",
            "expected": "invalid",
            "envelope": json.dumps(
                {"receipt_hash": rec_deny["receipt_hash"], "jws": new_deny_jws},
                sort_keys=True,
                separators=(",", ": "),
            ),
            "note": "controlled copy: signed payload tool field rewritten; "
            "JCS byte-equality + signature fail",
        }
    )

    # ------------------------------------------- unsupported_schema (crit bump)
    hdr = json.loads(b64d(tampered["jws"].split(".")[0]))
    hdr["crit"] = ["raucle/v1", "raucle/v2b"]
    hdr["raucle/v2b"] = "post-quantum-slot"
    p3, s3 = tampered["jws"].split(".")[1:]
    us = f"{b64e(json.dumps(hdr, separators=(',', ':'), sort_keys=True).encode())}.{p3}.{s3}"
    records.append(
        {
            "name": "unsupported_schema_crit",
            "expected": "unsupported_schema",
            "envelope": json.dumps(
                {"receipt_hash": tampered["receipt_hash"], "jws": us},
                sort_keys=True,
                separators=(",", ": "),
            ),
            "note": "controlled copy: JOSE header crit altered to a foreign raucle/v2b family; "
            "raises 'unknown critical header parameter(s)' before signature checks",
        }
    )

    # --------------------------------- unknown_key: exercised vs a v2-only registry
    records.append(
        {
            "name": "unknown_key_v2only",
            "expected": "unknown_key",
            "envelope": env[r_deny["receipt_id"]].decode(),
            "note": "verbatim genuine envelope; verified against a trust root containing ONLY "
            "key v2 (not the issuing key v1) — kid absent from archive at event time",
        }
    )

    # ------------------------------------- pending / unavailable (simulated)
    records.append(
        {
            "name": "pending_async_ingest",
            "expected": "pending",
            "simulated": True,
            "note": "async ingest is companion-side: envelope captured but verification not yet "
            "run; harness synthesises state pending (no raucle call)",
        }
    )
    records.append(
        {
            "name": "unavailable_store_gone",
            "expected": "unavailable",
            "simulated": True,
            "note": "evidence-plane object missing/unreadable at retrieval: harness synthesises "
            "state unavailable, never guessed",
        }
    )

    # ------------------------------------------------------------------ sanity
    sanity = _raucle().provenance.ProvenanceVerifier(
        public_keys={kid_v1: gw1.gate_identity.public_key_pem()}
    )
    for rec in records:
        if rec.get("simulated") or rec["name"] in (
            "invalid_sig_flip",
            "invalid_payload_tamper",
            "unsupported_schema_crit",
        ):
            continue  # expected to fail; verified by the conformance run
        tmp = work / "sanity.jsonl"
        tmp.write_text(rec["envelope"] + "\n")
        rep = sanity.verify_chain(tmp)
        assert rep.valid, (rec["name"], rep.to_dict()["errors"])

    corpus = FixtureCorpus(
        workspace=workspace,
        records=records,
        key_id=kid_v1,
        public_key_pem=gw1.gate_identity.public_key_pem(),
    )
    corpus.corpus_path.write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in records))
    return corpus


if __name__ == "__main__":
    import sys

    out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else pathlib.Path("fixtures")
    n = len(generate(out).records)
    print(f"wrote {out / 'corpus.jsonl'} ({n} fixtures) | raucle pin: {RAUCLE_DISTRIBUTION_PIN}")
