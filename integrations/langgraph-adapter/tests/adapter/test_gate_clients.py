# SPDX-License-Identifier: Apache-2.0
"""Gate-client unit tests: HttpGateClient (local HTTP), pin constant, latency config."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import ClassVar

import pytest
from oaa_langgraph_adapter import RAUCLE_DISTRIBUTION_PIN, GateDecision, HttpGateClient


class _GateHandler(BaseHTTPRequestHandler):
    decisions: ClassVar[dict] = {
        "decision": "allow",
        "receipt_hash": "sha256:r1",
        "reason": "ok",
        "latency_us": 42,
    }
    seen: ClassVar[dict] = {}

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen = body
        out = json.dumps(type(self).decisions).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # silence
        pass


@pytest.fixture()
def gate_server():
    server = HTTPServer(("127.0.0.1", 0), _GateHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}/v1/gate/check"
    server.shutdown()


def test_http_allow_with_receipt(gate_server):
    client = HttpGateClient(gate_server, timeout_s=2.0)
    d = client.check_tool_call(
        tool="read_file",
        args={"path": "/var/oaa-demo/synthetic/x"},
        call_id="c1",
        trace_id="",
        agent_id="a",
        source="t",
    )
    assert isinstance(d, GateDecision)
    assert d.decision == "allow"
    assert d.receipt_hash == "sha256:r1"
    assert "x_gate" not in d.raw  # raw is the server payload
    # correlation id forwarded and echoed as trace id when none supplied
    assert _GateHandler.seen["call_id"] == "c1"
    assert _GateHandler.seen["trace_id"] == "c1"
    assert _GateHandler.seen["distribution_pin"] == RAUCLE_DISTRIBUTION_PIN


def test_http_deny_decision_normalised(gate_server):
    _GateHandler.decisions = {"decision": "deny", "reason": "no policy"}
    client = HttpGateClient(gate_server, timeout_s=2.0)
    d = client.check_tool_call(
        tool="t", args={}, call_id="c2", trace_id="tr", agent_id="", source=""
    )
    assert d.decision == "deny"
    assert d.receipt_hash is None
    assert _GateHandler.seen["trace_id"] == "tr"


def test_http_unreachable_failmodes():
    good = HttpGateClient("http://127.0.0.1:1/nope", timeout_s=0.02, fail_open=False)
    assert (
        good.check_tool_call(
            tool="t", args={}, call_id="c", trace_id="", agent_id="", source=""
        ).decision
        == "deny"
    )
    bad = HttpGateClient("http://127.0.0.1:1/nope", timeout_s=0.02, fail_open=True)
    d = bad.check_tool_call(tool="t", args={}, call_id="c", trace_id="", agent_id="", source="")
    assert d.decision == "allow"
    assert d.error
    assert d.receipt_hash is None


def test_pin_constant_is_distribution_not_version():
    assert RAUCLE_DISTRIBUTION_PIN == "raucle 0.23.5 (git 63edacd)"


def test_default_timeout_is_latency_budget():
    client = HttpGateClient("http://127.0.0.1:1/x")
    assert client._timeout_s == pytest.approx(0.080)
