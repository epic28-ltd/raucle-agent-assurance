# SPDX-License-Identifier: Apache-2.0
"""Shared helpers for the oaa-ep-aec tests."""

from __future__ import annotations

import base64
import hashlib
import json
import pathlib


def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def fake_jws(payload: dict, kid: str = "test-key-1") -> str:
    """A structurally-valid compact JWS (signature NOT verified — unit-level
    fixture only; real signature verification is covered by the raucle
    integration test, which mints receipts with raucle itself)."""
    header = {"alg": "ES256", "kid": kid, "typ": "provenance-receipt/v1"}
    return f"{b64u(json.dumps(header).encode())}.{b64u(json.dumps(payload).encode())}.{b64u(b'unit-test-signature')}"


def make_store(store_dir: pathlib.Path, receipts: list[dict]) -> list[str]:
    """Write canonical {receipt_hash, jws} JSONL lines; return receipt hashes
    in store order."""
    store_dir.mkdir(parents=True, exist_ok=True)
    hashes: list[str] = []
    with open(store_dir / "store.jsonl", "wb") as fh:
        for payload in receipts:
            jws = fake_jws(payload)
            rec_hash = hashlib.sha256(jws.encode()).hexdigest()
            rec_hash = "sha256:" + rec_hash
            line = json.dumps({"receipt_hash": rec_hash, "jws": jws}, separators=(",", ":"))
            fh.write(line.encode() + b"\n")
            hashes.append(rec_hash)
    return hashes


def gate_payload(
    tool: str = "read_file",
    agent_id: str = "agent:evd",
    trace_id: str = "evd-trace-0001",
    decision: str = "allow",
    **xgate_extra,
) -> dict:
    return {
        "typ": "provenance-receipt/v1",
        "agent_id": agent_id,
        "operation": "guardrail_scan",
        "iat": 1793781666,
        "x_gate": {
            "acting_for": "",
            "agent_id": agent_id,
            "approval_id": "",
            "decision": decision,
            "policy": "policies.yaml",
            "reason": "ok",
            "rule_id": f"{tool}/{agent_id}/0",
            "tool": tool,
            "trace_id": trace_id,
            **xgate_extra,
        },
    }
