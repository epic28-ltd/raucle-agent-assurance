# SPDX-License-Identifier: Apache-2.0
"""OBS-03: adapter contract reuses for a second workflow (compliance-ticket-triage).

Minimal tests over examples/reference-agent/workflow_two.py — the workflow
runs locally (no langgraph, no raucle, no network): the gate is the
loopback-only synthetic ScopeGateClient from the example itself, exercising
the REAL adapter middleware paths (allow-with-receipt and deny-veto).
"""

import importlib.util
import pathlib
import sys

import pytest

_ADAPTER_SRC = (
    pathlib.Path(__file__).resolve().parents[2] / "integrations" / "langgraph-adapter" / "src"
)
if str(_ADAPTER_SRC) not in sys.path:
    sys.path.insert(0, str(_ADAPTER_SRC))

from oaa_langgraph_adapter import RaucleGateMiddleware  # noqa: E402

_HERE = pathlib.Path(__file__).resolve().parent
_WF = _HERE.parent.parent / "examples" / "reference-agent" / "workflow_two.py"

_spec = importlib.util.spec_from_file_location("workflow_two", _WF)
assert _spec is not None
wf = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(wf)


def _tool_attrs(recorder, name="tool-file_write"):
    spans = [s for s in recorder.spans if s["name"] == name and recorder._own(s)][-1:]
    assert spans, "gated tool span missing"
    return spans[0]["attributes"]


def test_normal_run_allow_signed_receipt_and_ledger_row():
    result = wf.run_workflow(deny=False)
    attrs = _tool_attrs(result["recorder"])
    assert attrs["oaa.verification"] == "signed"
    assert str(attrs["oaa.receipt_hash"]).startswith("sha256:")
    assert attrs["oaa.policy"] == "compliance-ticket-triage/file_write.yaml"
    assert result["gate_decision"] == "allow"
    assert result["ledger_has_write_row"]  # tool body actually ran


def test_designed_failure_deny_veto_and_ledger_absence():
    result = wf.run_workflow_deny()
    attrs = _tool_attrs(result["recorder"])
    assert result["gate_decision"] == "deny"
    assert "oaa.receipt_hash" not in attrs  # no verification state on a veto
    assert "oaa.verification" not in attrs
    assert result["ledger_has_write_row"] is False  # the ABSENCE row: tool never ran


def test_contract_reuse_surfaces():
    # Same adapter-contract shapes as workflow one: sink callbacks, client,
    # middleware — all unchanged from integrations/langgraph-adapter.
    sink = wf.SpanAttributeSink(wf.SpanRecorder())
    assert hasattr(sink, "set_tool_attributes")
    assert hasattr(wf.AuditSink(), "on_gate_event")
    assert hasattr(wf.ScopeGateClient(), "check_tool_call")
    assert hasattr(RaucleGateMiddleware, "wrap_tool_call")  # reused: real adapter class

    # Different shape: multi-step (two retrievers before the LLM and tool).
    result = wf.run_workflow(deny=False)
    own = [s for s in result["recorder"].spans if result["recorder"]._own(s)]
    # children end before the root span closes, so compare as a set of names
    assert sorted(s["name"] for s in own) == sorted(
        [
            "oaa.agent.two.main",
            "retrieve-ticket",
            "fetch-customer-context",
            "stub-llm-propose",
            "tool-file_write",
        ]
    )
    root = next(s["attributes"] for s in own if s["parent_span_id"] is None)
    assert root["oaa.run_id"].startswith(wf.RUN_ID_PREFIX)
    assert root["oaa.release_version"]
    assert root["openinference.span.kind"] == "AGENT"


def test_deny_mode_is_explicit_not_run():
    with pytest.raises(ValueError):
        wf.run_workflow(deny=True)
