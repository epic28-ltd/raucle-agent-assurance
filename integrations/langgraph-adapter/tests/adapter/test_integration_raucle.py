# SPDX-License-Identifier: Apache-2.0
"""Skippable integration test against the pinned raucle worktree.

Runs a REAL allow and a REAL deny through ``RaucleGateway.check_tool_call``
(v0.23.5, git 63edacd) wrapped by ``InProcessRaucleGate`` and enforced by
``RaucleGateMiddleware``. Skipped (never failed) when the pinned raucle is
not importable: set PYTHONPATH to the worktree, or point RAUCLE_WORKTREE at it.
"""

import base64
import json
import pathlib

import pytest

pytest.importorskip(
    "raucle",
    reason="raucle (pinned v0.23.5, git 63edacd) not installed — "
    "PYTHONPATH=~/Projects/oaa-spike-4nov/evd/raucle-63edacd",
)

from oaa_langgraph_adapter import InProcessRaucleGate, RaucleGateMiddleware

POLICIES = """
version: 1
issuer: k3.demo
policies:
  - tool: read_file
    agent_id: agent:k3
    ttl_seconds: 300
    constraints:
      allow:
        path: ["{allowed}"]
"""


class Harness:
    """Middleware wired to a real in-process RaucleGateway."""

    def __init__(self):
        raucle = pytest.importorskip("raucle")
        pytest.importorskip("raucle.gateway")
        import tempfile  # noqa: PLC0415 (module-level raucle skip guard first)

        tmp = pathlib.Path(tempfile.mkdtemp(prefix="raucle-k3-"))
        self.allowed = tmp / "allowed.txt"
        self.allowed.write_text("ok")
        policy_file = tmp / "policies.yaml"
        policy_file.write_text(POLICIES.format(allowed=str(self.allowed)))
        cfg = raucle.gateway.GatewayConfig(
            host="127.0.0.1",
            admin_api_key="k",
            signer_backend="local",
            policy_file=str(policy_file),
            receipt_store=str(tmp / "receipts.jsonl"),
            audit_chain=str(tmp / "audit.jsonl"),
            registry_path=str(tmp / "registry.jsonl"),
            emit_receipts=True,
        )
        gateway = raucle.gateway.RaucleGateway(cfg)
        self.gate = InProcessRaucleGate(gateway, agent_id="agent:k3")
        self.spans = _Sink()
        self.audit = _Sink()
        self.mw = RaucleGateMiddleware(self.gate, span_sink=self.spans, audit_sink=self.audit)


class _Sink:
    def __init__(self) -> None:
        self.attrs: dict[str, dict] = {}
        self.events: list[dict] = []

    def set_tool_attributes(self, call_id, attributes):
        self.attrs[call_id] = dict(attributes)

    def on_gate_event(self, event):
        self.events.append(dict(event))


@pytest.fixture()
def h():
    return Harness()


def _req(name, args, cid):
    return {"tool_call": {"name": name, "args": args, "id": cid}}


def test_real_allow_through_raucle_gateway(h):
    """A policy-allowed call passes, runs the tool, and carries a signed receipt."""
    runs = []
    result = h.mw.wrap_tool_call(
        _req("read_file", {"path": str(h.allowed)}, "k3-allow-1"), runs.append
    )
    assert len(runs) == 1, "tool body must run on allow"
    assert result is None  # execute() was the runs.append stub

    attrs = h.spans.attrs["k3-allow-1"]
    assert attrs["oaa.verification"] == "signed"
    assert attrs["oaa.receipt_hash"]
    assert attrs["oaa.trace_id"] == "k3-allow-1"

    ev = h.audit.events[0]
    assert ev["decision"] == "allow"
    assert ev["trace_id"] == "k3-allow-1"  # correlation id reached the gate


def test_real_deny_through_raucle_gateway(h):
    """A policy-violating path is denied and the tool body NEVER runs."""
    runs = []
    out = h.mw.wrap_tool_call(
        _req("read_file", {"path": "/var/oaa-demo/definitely-not-allowed.txt"}, "k3-deny-1"),
        runs.append,
    )
    assert runs == [], "tool body must not run on deny"
    assert "denied by Raucle Agent Trust gate" in str(out["content"])
    ev = h.audit.events[0]
    assert ev["decision"] == "deny"
    assert ev["trace_id"] == "k3-deny-1"


def test_real_unknown_tool_deny(h):
    runs = []
    out = h.mw.wrap_tool_call(_req("no_such_tool", {}, "k3-deny-2"), runs.append)
    assert runs == [], "tool body must not run on deny"
    assert "denied by Raucle Agent Trust gate" in str(out["content"])


def test_receipt_keyed_by_correlation_id(h):
    """The gate's signed receipt row records the correlation id we supplied."""
    d = h.gate.check_tool_call(
        tool="read_file",
        args={"path": str(h.allowed)},
        call_id="corr-77",
        trace_id="",
        agent_id="agent:k3",
        source="langgraph",
    )
    assert d.decision == "allow"
    assert d.receipt_hash
    store = pathlib.Path(h.gate._gateway.config.receipt_store)
    for line in store.read_text().splitlines():
        rec = json.loads(line)
        payload = json.loads(
            base64.urlsafe_b64decode(
                rec["jws"].split(".")[1] + "=" * (-len(rec["jws"].split(".")[1]) % 4)
            )
        )
        if payload.get("x_gate", {}).get("trace_id") == "corr-77":
            break
    else:
        pytest.fail("no receipt bound to correlation id corr-77 in the signed store")
