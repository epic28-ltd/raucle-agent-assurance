#!/usr/bin/env python3
"""OBS-03: second synthetic workflow instrumented through the adapter contract.

``compliance-ticket-triage`` — a DIFFERENT shape from the OBS-01
``reference_agent`` (single AGENT root -> LLM / RETRIEVER / TOOL children,
one flat level): this workflow is multi-step,

    AGENT root
      -> RETRIEVER  retrieve-ticket
      -> RETRIEVER  fetch-customer-context
      -> LLM (stub) propose-action
      -> TOOL       file_write   (gated via RaucleGateMiddleware)
    (workflow exit)

Everything that made the OBS-01 trace contract work is reused WITHOUT touching
the adapter or core instrumentation packages:

- OpenInference span kinds (attribute names mirror
  ``openinference.semconv.trace``; they are literal strings here so the
  example has zero external runtime dependencies — the local Langfuse push
  uses the same stock OTLP exporter as workflow one and is skippable);
- the ``oaa.*`` attribute namespace with ``run_id`` / ``release_version``
  (run-two prefix: ``oaa-run2-*``);
- the SAME ``SpanAttributeSink``-style callback contract
  (``set_tool_attributes(call_id, attributes)``) and the adapter's
  ``AuditSink`` contract (``on_gate_event(event)``) — both implemented here
  as plain classes, exactly as ``integrations/langgraph-adapter`` defines
  them via Protocols;
- the adapter's ``RaucleGateMiddleware`` + ``GateClient`` protocol: the gate
  is a local in-memory policy client (loopback-only synthetic gate), so the
  enforcement path — one gate call, veto by not executing, signed-receipt
  span attributes, denial audit row — is the real adapter path.

Designed failure path: in deny mode the proposed write is OUT OF SCOPE; the
gate denies, the middleware vetoes (the write executor NEVER runs), and the
tool-side file-write audit ledger shows the row's ABSENCE — the negative
evidence OBS-03 asks for.
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import uuid

from oaa_langgraph_adapter import (
    GateDecision,
    RaucleGateMiddleware,
)
from opentelemetry import trace as tr
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.export import SpanProcessor as SDKSpanProcessor

BASE = pathlib.Path(__file__).resolve().parent

# Literal OpenInference semconv attribute names (mirror openinference.semconv.trace;
# no external package import needed for this example).
OI_SPAN_KIND = "openinference.span.kind"
OI_LLM_MODEL_NAME = "llm.model_name"
OI_LLM_INPUT_MESSAGES = "llm.input_messages"
OI_LLM_OUTPUT_MESSAGES = "llm.output_messages"
OI_RETRIEVAL_DOCUMENTS = "retrieval.documents"
OI_TOOL_NAME = "tool.name"
OI_TOOL_PARAMETERS = "tool.parameters"

RELEASE_VERSION = "v0.23.5+63edacd"
SERVICE_NAME = "oaa-workflow-two"
TRACER_NAME = "oaa.workflowtwo"
RUN_ID_PREFIX = "oaa-run2"  # run-two prefix distinguishes workflow two from OBS-01
TRACE_LABEL_PREFIX = "oaa-trace2"

# In-scope file root for this workflow; anything outside it is out of scope
# and denied by the gate.
SCOPE_ROOT = "/tmp/oaa-scope/compliance-tickets"
OUT_OF_SCOPE_PATH = "/tmp/oaa-scope/finance/master-ledger.csv"
NORMAL_WRITE_PATH = f"{SCOPE_ROOT}/ticket-42/proposed-action.md"


# --- adapter-contract callbacks (same shapes as workflow one) ---------------


class SpanAttributeSink:
    """Same contract as the adapter's ``SpanAttributeSink`` protocol.

    Routes gate-issued attributes onto the in-memory span record for
    ``call_id`` — and onto the live OTel span when the exporter is enabled.
    """

    def __init__(self, recorder: SpanRecorder) -> None:
        self._recorder = recorder

    def set_tool_attributes(self, call_id: str, attributes: dict[str, object]) -> None:
        self._recorder.attach_tool_attributes(call_id, dict(attributes))


class AuditSink:
    """Same contract as the adapter's ``AuditSink`` protocol."""

    def __init__(self) -> None:
        self.events: list[dict[str, object]] = []

    def on_gate_event(self, event: dict[str, object]) -> None:
        self.events.append(dict(event))


class FileWriteLedger:
    """Tool-side audit ledger: one row per ACTUAL write.

    The row is appended only by the executor inside the gated tool body, so
    on a gate deny the ledger's absence of that path is the negative proof
    (the middleware vetoes by not calling ``execute``).
    """

    def __init__(self) -> None:
        self.rows: list[dict[str, str]] = []

    def record_write(self, path: str, run_id: str) -> None:
        self.rows.append({"path": path, "run_id": run_id})

    def has_row(self, path: str) -> bool:
        return any(r["path"] == path for r in self.rows)


class ScopeGateClient:
    """Loopback-only synthetic gate implementing the adapter ``GateClient`` protocol.

    Policy: ``file_write`` inside ``SCOPE_ROOT`` is allowed with a signed
    (synthetic, self-hash) receipt; anything else denies. It records every
    request so the smoke script can show the gate saw the denied call.
    """

    scope_root = SCOPE_ROOT

    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []

    def check_tool_call(
        self,
        *,
        tool: str,
        args: dict[str, object],
        call_id: str,
        trace_id: str,
        agent_id: str,
        source: str,
    ) -> GateDecision:
        self.requests.append({"tool": tool, "args": args, "call_id": call_id, "trace_id": trace_id})
        if tool == "file_write":
            path = str(args.get("path", ""))
            if path.startswith(self.scope_root):
                receipt = "sha256:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"{call_id}:{path}").hex)
                return GateDecision(
                    decision="allow",
                    reason="in-scope path",
                    receipt_hash=receipt,
                    latency_us=120,
                    raw={"policy": "compliance-ticket-triage/file_write.yaml"},
                )
            return GateDecision(
                decision="deny", reason="out of scope: outside compliance-ticket root"
            )
        return GateDecision(decision="deny", reason="tool not in workflow policy")


def _actual_file_write(path: str, content: str, ledger: FileWriteLedger, run_id: str) -> str:
    """The real tool body. Only reachable through an allowed gate decision."""
    ledger.record_write(path, run_id)
    return f"wrote {len(content)} bytes to {path}"


# --- OTel plumbing (same shape as workflow one, plus a local recorder) ------


class SpanRecorder:
    """In-process span sink so the smoke script works without any backend.

    Wraps spans as nested dicts; gate attributes arrive later via the
    SpanAttributeSink contract and are grafted onto the recorded span.
    """

    def __init__(self, run_id: str | None = None) -> None:
        self.spans: list[dict[str, object]] = []
        # The shared TracerProvider accumulates per-run processors, so a recorder
        # filters to its own run when it knows its run_id.
        self.run_id = run_id
        self._trace_id: str | None = None
        # Gate attributes arrive DURING the tool span (before on_end), so they
        # queue here and graft when the span lands.
        self._pending: dict[str, dict[str, object]] = {}

    def _own(self, rec: dict[str, object]) -> bool:
        # The shared TracerProvider accumulates per-run processors (OTel allows only
        # one provider), so a recorder filters to its own trace. Children spans do
        # not carry oaa.run_id, so the ROOT trace_id is the discriminator: every
        # span of a run shares it.
        if self._trace_id is None:
            return True  # learning our trace id — never discard the root
        return rec.get("trace_id") == self._trace_id

    def add(
        self,
        span_id: str,
        parent_span_id: str | None,
        trace_id: str,
        name: str,
        kind: str,
        attributes: dict[str, object],
    ) -> dict[str, object]:
        rec = {
            "name": name,
            "kind": kind,
            "span_id": span_id,
            "parent_span_id": parent_span_id,
            "trace_id": trace_id,
            "attributes": attributes,
        }
        if (
            not parent_span_id
            and self._trace_id is None
            # Only ADOPT this root when it is really our run (other runs'
            # spans flow through the shared provider first).
            and (self.run_id is None or attributes.get("oaa.run_id") == self.run_id)
        ):
            self._trace_id = trace_id
        call_id = attributes.get("oaa.tool_call_id")
        if call_id in self._pending:
            attributes.update(self._pending.pop(call_id))
        self.spans.append(rec)
        return rec

    def attach_tool_attributes(self, call_id: str, attributes: dict[str, object]) -> None:
        for rec in self.spans[::-1]:
            if not self._own(rec):
                continue
            if rec["attributes"].get("oaa.tool_call_id") == call_id:
                rec["attributes"].update(attributes)
                return
        self._pending[call_id] = dict(attributes)

    def tool_attributes(self, call_id: str) -> dict[str, object] | None:
        for rec in self.spans:
            if not self._own(rec):
                continue
            if rec["attributes"].get("oaa.tool_call_id") == call_id:
                return rec["attributes"]
        return None

    def oaa_readback(self) -> dict[str, object]:
        """All ``oaa.*`` attributes seen in the run, keyed per span."""
        out: dict[str, object] = {}
        for rec in self.spans:
            if not self._own(rec):
                continue
            oaa = {k: v for k, v in rec["attributes"].items() if k.startswith("oaa.")}
            if oaa:
                out[str(rec["name"])] = oaa
        return out

    def tree_text(self) -> str:
        roots = [s for s in self.spans if not s["parent_span_id"] and self._own(s)]
        lines: list[str] = []

        def emit(rec: dict[str, object], depth: int) -> None:
            kind = rec["attributes"].get(OI_SPAN_KIND, rec["kind"])
            ver = rec["attributes"].get("oaa.verification", "")
            suffix = f" verification={ver}" if ver else ""
            lines.append("  " * depth + f"{rec['name']} [{kind}]{suffix}")
            for child in self.spans:
                if child["parent_span_id"] == rec["span_id"] and self._own(child):
                    emit(child, depth + 1)

        for root in roots:
            emit(root, 0)
        return "\n".join(lines)


_PROVIDER: TracerProvider | None = None


def _shared_provider() -> TracerProvider:
    """One TracerProvider per process; OTel allows only one global provider."""
    global _PROVIDER
    if _PROVIDER is None:
        _PROVIDER = TracerProvider(
            resource=Resource.create(
                {"service.name": SERVICE_NAME, "service.version": RELEASE_VERSION}
            )
        )
        tr.set_tracer_provider(_PROVIDER)
    return _PROVIDER


def _build_provider(
    push: bool, lf_url: str, creds: dict[str, str], run_id: str | None = None
) -> tuple[TracerProvider, SpanRecorder]:
    """Register a per-run recorder (and the skippable OTLP pusher) on the shared provider."""
    provider = _shared_provider()
    recorder = SpanRecorder(run_id=run_id or None)
    if push:
        pusher = BatchSpanProcessor(
            OTLPSpanExporter(
                endpoint=f"{lf_url}/api/public/otel/v1/traces",
                headers={
                    "Authorization": "Basic "
                    + base64.b64encode(
                        f"{creds['LANGFUSE_INIT_PROJECT_PUBLIC_KEY']}:"
                        f"{creds['LANGFUSE_INIT_PROJECT_SECRET_KEY']}".encode()
                    ).decode()
                },
                timeout=20,
            )
        )
        provider.add_span_processor(_RecordingProcessor(recorder, push_processor=pusher))
    else:
        provider.add_span_processor(_RecordingProcessor(recorder))
    return provider, recorder


class _RecordingProcessor(SDKSpanProcessor):
    """Capture spans locally (always); forward via a BatchSpanProcessor when push is on."""

    def __init__(
        self,
        recorder: SpanRecorder,
        push_processor: SDKSpanProcessor | None = None,
    ) -> None:
        self._recorder = recorder
        self._push = push_processor

    def on_start(self, span, parent_context) -> None:
        pass

    def on_end(self, span) -> None:
        ctx = span.get_span_context()
        parent = span.parent
        self._recorder.add(
            span_id=format(ctx.span_id, "016x"),
            parent_span_id=format(parent.span_id, "016x") if parent else None,
            trace_id=format(ctx.trace_id, "032x"),
            name=span.name,
            kind=str(
                span.attributes.get(OI_SPAN_KIND, "INTERNAL") if span.attributes else "INTERNAL"
            ),
            attributes=dict(span.attributes or {}),
        )
        if self._push is not None:
            self._push.on_end(span)

    def shutdown(self) -> None:
        if self._push is not None:
            self._push.force_flush()

    def force_flush(self, timeout_millis: int | None = None) -> bool:
        if self._push is not None:
            self._push.force_flush(timeout_millis)
        return True


def _flush_run(provider: TracerProvider) -> None:
    """Flush the shared provider after a run (no shutdown — later runs reuse it)."""
    provider.force_flush()


def _load_langfuse_creds() -> dict[str, str] | None:
    """Credentials for the SKIPPABLE local Langfuse push (obs.env or env vars)."""
    obs_env = BASE / "obs.env"
    creds: dict[str, str] = {}
    if obs_env.exists():
        for line in obs_env.read_text().splitlines():
            k, _, v = line.partition("=")
            creds[k] = v
    for k in ("LANGFUSE_INIT_PROJECT_PUBLIC_KEY", "LANGFUSE_INIT_PROJECT_SECRET_KEY"):
        if os.environ.get(k):
            creds[k] = os.environ[k]
    if not creds.get("LANGFUSE_INIT_PROJECT_PUBLIC_KEY") or not creds.get(
        "LANGFUSE_INIT_PROJECT_SECRET_KEY"
    ):
        return None
    return creds


# --- the workflow itself ----------------------------------------------------


def run_workflow(*, deny: bool, push: bool = False, lf_url: str = "http://localhost:3301") -> dict:
    """Run compliance-ticket-triage once.

    ``deny=False``: in-scope proposed write — gate allows with receipt, the
    tool body runs, a ledger row appears. ``deny=True``: OUT OF SCOPE write —
    gate denies, middleware vetoes, the ledger shows the row's ABSENCE.
    """
    if deny:
        raise ValueError("deny=True: out-of-scope writes are designed failure path")

    run_id = f"{RUN_ID_PREFIX}-{uuid.uuid4().hex[:12]}"
    trace_label = f"{TRACE_LABEL_PREFIX}-{uuid.uuid4().hex[:16]}"
    session_id = f"sess2-{run_id}"
    provider, recorder = _build_provider(push, lf_url, _load_langfuse_creds() or {}, run_id=run_id)
    tracer = tr.get_tracer(TRACER_NAME, "1.0.0")
    ledger = FileWriteLedger()
    audits = AuditSink()
    agent_id, source = "agent:compliance-ticket-triage", "langgraph"

    with tracer.start_as_current_span(
        "oaa.agent.two.main",
        attributes={
            OI_SPAN_KIND: "AGENT",
            "oaa.run_id": run_id,
            "oaa.release_version": RELEASE_VERSION,
            "oaa.trace_label": trace_label,
            "oaa.content_class": "synthetic_public",
            "langfuse.session.id": session_id,
            "langfuse.user.id": "user-craig-oaa",
        },
    ):
        ticket_span = tracer.start_span(
            "retrieve-ticket",
            attributes={
                OI_SPAN_KIND: "RETRIEVER",
                OI_RETRIEVAL_DOCUMENTS: json.dumps([{"doc.content": "ticket-42-brief"}]),
                "oaa.content_class": "synthetic_public",
            },
        )
        ticket_span.end()

        customer_span = tracer.start_span(
            "fetch-customer-context",
            attributes={
                OI_SPAN_KIND: "RETRIEVER",
                OI_RETRIEVAL_DOCUMENTS: json.dumps([{"doc.content": "cust-7-context"}]),
                "oaa.content_class": "synthetic_public",
            },
        )
        customer_span.end()

        llm_span = tracer.start_span(
            "stub-llm-propose",
            attributes={
                OI_SPAN_KIND: "LLM",
                OI_LLM_MODEL_NAME: "synthetic-stub-2",
                OI_LLM_INPUT_MESSAGES: json.dumps(
                    [{"role": "user", "content": "SYNTHETIC_PROMPT_NO_SECRET"}]
                ),
                OI_LLM_OUTPUT_MESSAGES: json.dumps(
                    [{"role": "assistant", "content": "SYNTHETIC_PROPOSAL_OK"}]
                ),
                "oaa.stub": True,
            },
        )
        llm_span.end()

        # Final action: a gated file_write through the SAME adapter contract.
        write_path = NORMAL_WRITE_PATH
        call_id = f"call2-file_write-{uuid.uuid4().hex[:8]}"
        mw = RaucleGateMiddleware(
            ScopeGateClient(),
            agent_id=agent_id,
            source=source,
            fail_open=False,
            on_deny="message",
            span_sink=SpanAttributeSink(recorder),
            audit_sink=audits,
        )
        with tracer.start_as_current_span(
            "tool-file_write",
            attributes={
                OI_SPAN_KIND: "TOOL",
                OI_TOOL_NAME: "file_write",
                OI_TOOL_PARAMETERS: json.dumps({"path": write_path}),
                "oaa.content_class": "synthetic_public",
                "oaa.tool_call_id": call_id,
            },
        ):
            request = {
                "tool_call": {"name": "file_write", "args": {"path": write_path}, "id": call_id}
            }
            result = mw.wrap_tool_call(
                request,
                lambda r: _actual_file_write(
                    path=r["tool_call"]["args"]["path"],
                    content="proposed-actions-v1",
                    ledger=ledger,
                    run_id=run_id,
                ),
            )
        gate_event = audits.events[0] if audits.events else {}

    _flush_run(provider)

    return {
        "mode": "normal",
        "run_id": run_id,
        "trace_label": trace_label,
        "tool_result": result,
        "gate_decision": gate_event.get("decision"),
        "receipt_hash": gate_event.get("receipt_hash"),
        "ledger_rows": ledger.rows,
        "ledger_has_write_row": ledger.has_row(write_path),
        "recorder": recorder,
    }


def run_workflow_deny(*, push: bool = False, lf_url: str = "http://localhost:3301") -> dict:
    """Designed failure path: gate deny on an out-of-scope write (absence row)."""
    run_id = f"{RUN_ID_PREFIX}-{uuid.uuid4().hex[:12]}"
    trace_label = f"{TRACE_LABEL_PREFIX}-deny-{uuid.uuid4().hex[:16]}"
    session_id = f"sess2-{run_id}"
    provider, recorder = _build_provider(push, lf_url, _load_langfuse_creds() or {}, run_id=run_id)
    tracer = tr.get_tracer(TRACER_NAME, "1.0.0")
    ledger = FileWriteLedger()
    audits = AuditSink()
    agent_id, source = "agent:compliance-ticket-triage", "langgraph"

    with tracer.start_as_current_span(
        "oaa.agent.two.main",
        attributes={
            OI_SPAN_KIND: "AGENT",
            "oaa.run_id": run_id,
            "oaa.release_version": RELEASE_VERSION,
            "oaa.trace_label": trace_label,
            "oaa.content_class": "synthetic_public",
            "langfuse.session.id": session_id,
            "langfuse.user.id": "user-craig-oaa",
        },
    ):
        t1 = tracer.start_span(
            "retrieve-ticket",
            attributes={
                OI_SPAN_KIND: "RETRIEVER",
                OI_RETRIEVAL_DOCUMENTS: json.dumps([{"doc.content": "ticket-42-brief"}]),
                "oaa.content_class": "synthetic_public",
            },
        )
        t1.end()
        t2 = tracer.start_span(
            "fetch-customer-context",
            attributes={
                OI_SPAN_KIND: "RETRIEVER",
                OI_RETRIEVAL_DOCUMENTS: json.dumps([{"doc.content": "cust-7-context"}]),
                "oaa.content_class": "synthetic_public",
            },
        )
        t2.end()
        llm = tracer.start_span(
            "stub-llm-propose",
            attributes={
                OI_SPAN_KIND: "LLM",
                OI_LLM_MODEL_NAME: "synthetic-stub-2",
                OI_LLM_INPUT_MESSAGES: json.dumps(
                    [{"role": "user", "content": "SYNTHETIC_PROMPT_NO_SECRET"}]
                ),
                OI_LLM_OUTPUT_MESSAGES: json.dumps(
                    [{"role": "assistant", "content": "SYNTHETIC_PROPOSAL_OUT_OF_SCOPE"}]
                ),
                "oaa.stub": True,
            },
        )
        llm.end()

        # DESIGNED FAILURE: out-of-scope write -> gate deny -> veto/absence.
        call_id = f"call2-file_write-deny-{uuid.uuid4().hex[:8]}"
        mw = RaucleGateMiddleware(
            ScopeGateClient(),
            agent_id=agent_id,
            source=source,
            fail_open=False,
            on_deny="message",
            span_sink=SpanAttributeSink(recorder),
            audit_sink=audits,
        )
        with tracer.start_as_current_span(
            "tool-file_write",
            attributes={
                OI_SPAN_KIND: "TOOL",
                OI_TOOL_NAME: "file_write",
                OI_TOOL_PARAMETERS: json.dumps({"path": OUT_OF_SCOPE_PATH}),
                "oaa.content_class": "synthetic_public",
                "oaa.tool_call_id": call_id,
            },
        ):
            request = {
                "tool_call": {
                    "name": "file_write",
                    "args": {"path": OUT_OF_SCOPE_PATH},
                    "id": call_id,
                }
            }
            result = mw.wrap_tool_call(
                request,
                lambda r: _actual_file_write(
                    path=r["tool_call"]["args"]["path"],
                    content="proposed-actions-v1",
                    ledger=ledger,
                    run_id=run_id,
                ),
            )
        gate_event = audits.events[0] if audits.events else {}

    _flush_run(provider)

    return {
        "mode": "deny",
        "run_id": run_id,
        "trace_label": trace_label,
        "tool_result": str(result),
        "gate_decision": gate_event.get("decision"),
        "receipt_hash": gate_event.get("receipt_hash"),
        "ledger_rows": ledger.rows,
        "ledger_has_write_row": ledger.has_row(OUT_OF_SCOPE_PATH),
        "recorder": recorder,
    }
