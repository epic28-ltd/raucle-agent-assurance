#!/usr/bin/env python3
"""OBS-01 reference agent: synthetic OTel trace with OpenInference span kinds, direct OTLP to Langfuse.

Emits one trace: AGENT root -> LLM (stub), RETRIEVER, TOOL children, with an
oaa.* namespace (run_id/release_version) and redaction-controlled attribute
(oaa.content_class only — no raw secret is ever an attribute).
Writes the emitted attribute set to originals.json for round-trip diffing (P1).
"""

import base64
import json
import os
import pathlib
import uuid

from openinference.semconv.trace import SpanAttributes as SA
from opentelemetry import trace as tr
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

BASE = pathlib.Path(__file__).resolve().parent

CREDS = {}
for line in (BASE / "obs.env").read_text().splitlines():
    k, _, v = line.partition("=")
    CREDS[k] = v

BASEURL = os.environ.get("OAA_LF_URL", "http://localhost:3301")
RUN_ID = f"oaa-run-{uuid.uuid4().hex[:12]}"
RELEASE_VERSION = "v0.23.5+63edacd"
SESSION_ID = f"sess-{RUN_ID}"

provider = TracerProvider(
    resource=Resource.create(
        {
            "service.name": "oaa-reference-agent",
            "service.version": RELEASE_VERSION,
        }
    )
)
tr.set_tracer_provider(provider)
tracer = tr.get_tracer("oaa.reference", "1.0.0")
exporter = OTLPSpanExporter(
    endpoint=f"{BASEURL}/api/public/otel/v1/traces",
    headers={
        "Authorization": "Basic "
        + base64.b64encode(
            f"{CREDS['LANGFUSE_INIT_PROJECT_PUBLIC_KEY']}:{CREDS['LANGFUSE_INIT_PROJECT_SECRET_KEY']}".encode()
        ).decode()
    },
    timeout=20,
)
provider.add_span_processor(BatchSpanProcessor(exporter))

TRACE_LABEL = f"oaa-trace-{uuid.uuid4().hex[:16]}"

originals = {
    "run_id": RUN_ID,
    "release_version": RELEASE_VERSION,
    "trace_label": TRACE_LABEL,
    "spans": [],
}

with tracer.start_as_current_span(
    "oaa.agent.main",
    attributes={
        SA.OPENINFERENCE_SPAN_KIND: "AGENT",
        "oaa.run_id": RUN_ID,
        "oaa.release_version": RELEASE_VERSION,
        "oaa.trace_label": TRACE_LABEL,
        "oaa.content_class": "synthetic_public",  # redaction control: class only, never a raw secret
        "langfuse.session.id": SESSION_ID,
        "langfuse.user.id": "user-craig-oaa",
    },
) as agent_span:
    ctx = agent_span.get_span_context()
    originals["otel_trace_id"] = format(ctx.trace_id, "032x")
    originals["root_span_id"] = format(ctx.span_id, "016x")
    # stub LLM span (no real model API)
    llm_in = json.dumps([{"role": "user", "content": "SYNTHETIC_PROMPT_NO_SECRET"}])
    llm_out = json.dumps([{"role": "assistant", "content": "SYNTHETIC_RESPONSE_OK"}])
    with tracer.start_as_current_span(
        "stub-llm-chat",
        attributes={
            SA.OPENINFERENCE_SPAN_KIND: "LLM",
            SA.LLM_MODEL_NAME: "synthetic-stub-1",
            SA.LLM_INPUT_MESSAGES: llm_in,
            SA.LLM_OUTPUT_MESSAGES: llm_out,
            "oaa.stub": True,
        },
    ):
        pass
    with tracer.start_as_current_span(
        "retrieve-kb",
        attributes={
            SA.OPENINFERENCE_SPAN_KIND: "RETRIEVER",
            SA.RETRIEVAL_DOCUMENTS: json.dumps([{"doc.content": "synthetic-doc-1"}]),
            "oaa.content_class": "synthetic_public",
        },
    ):
        pass
    with tracer.start_as_current_span(
        "tool-read_file",
        attributes={
            SA.OPENINFERENCE_SPAN_KIND: "TOOL",
            SA.TOOL_NAME: "read_file",
            SA.TOOL_PARAMETERS: json.dumps({"path": "/tmp/report.txt"}),
            "oaa.content_class": "synthetic_public",
        },
    ):
        pass

originals["spans"] = [
    {
        "name": "oaa.agent.main",
        "kind": "AGENT",
        "attrs": {
            "openinference.span.kind": "AGENT",
            "oaa.run_id": RUN_ID,
            "oaa.release_version": RELEASE_VERSION,
            "oaa.trace_label": TRACE_LABEL,
            "oaa.content_class": "synthetic_public",
            "langfuse.session.id": SESSION_ID,
            "langfuse.user.id": "user-craig-oaa",
        },
    },
    {
        "name": "stub-llm-chat",
        "kind": "LLM",
        "attrs": {
            "openinference.span.kind": "LLM",
            "llm.model_name": "synthetic-stub-1",
            "llm.input_messages": llm_in,
            "llm.output_messages": llm_out,
            "oaa.stub": True,
        },
    },
    {
        "name": "retrieve-kb",
        "kind": "RETRIEVER",
        "attrs": {
            "openinference.span.kind": "RETRIEVER",
            "retrieval.documents": json.dumps([{"doc.content": "synthetic-doc-1"}]),
            "oaa.content_class": "synthetic_public",
        },
    },
    {
        "name": "tool-read_file",
        "kind": "TOOL",
        "attrs": {
            "openinference.span.kind": "TOOL",
            "tool.name": "read_file",
            "tool.parameters": json.dumps({"path": "/tmp/report.txt"}),
            "oaa.content_class": "synthetic_public",
        },
    },
]

provider.force_flush()
provider.shutdown()

(BASE / "originals.json").write_text(json.dumps(originals, indent=2))
print("EMITTED otel_trace_id:", originals["otel_trace_id"])
print("root_span_id:", originals["root_span_id"])
print("run_id:", RUN_ID, "label:", TRACE_LABEL)
