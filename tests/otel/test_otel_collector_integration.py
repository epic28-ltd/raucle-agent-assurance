# SPDX-License-Identifier: Apache-2.0
"""Live OTLP/HTTP round-trip test, enabled only by the collector CI job."""

from __future__ import annotations

import os

import pytest
from oaa_instrumentation.otel_export import (
    ENV_OTLP_ENDPOINT,
    ENV_OTLP_MAX_ATTEMPTS,
    ENV_OTLP_TIMEOUT_MS,
    configure_tracing_from_env,
)

AWS_KEY_FIXTURE = "AKIAIOSFODNN7EXAMPLE"
BEARER_FIXTURE = "Bearer integration-secret-token-value-123456"


@pytest.mark.skipif(
    not os.environ.get("OAA_OTLP_ENDPOINT"),
    reason="live OTLP collector endpoint is configured only in the collector CI job",
)
def test_real_otlp_http_round_trip_preserves_parent_and_redacts() -> None:
    """Send real spans over OTLP/HTTP; collector output is asserted by the workflow."""
    setup = configure_tracing_from_env(
        {
            ENV_OTLP_ENDPOINT: os.environ["OAA_OTLP_ENDPOINT"],
            ENV_OTLP_MAX_ATTEMPTS: "1",
            ENV_OTLP_TIMEOUT_MS: "5000",
        },
        install_global=False,
        batched=False,
        resource_attributes={"service.name": "oaa-otel-collector-ci"},
    )
    assert setup is not None

    with setup.tracer.start_as_current_span("oaa.gate.parent") as parent:
        parent_context = parent.get_span_context()
        with setup.tracer.start_as_current_span("oaa.gate.decision") as child:
            child.set_attributes(
                {
                    "oaa.gate.decision": "allow",
                    "oaa.tool": "read_file",
                    "oaa.agent_id": "agent:otel-ci",
                    "oaa.metadata.authorization": BEARER_FIXTURE,
                    "exception.message": f"synthetic failure with {AWS_KEY_FIXTURE}",
                }
            )
            child_context = child.get_span_context()

    setup.shutdown()

    assert setup.exporter.metrics["batches_dropped"] == 0
    assert {item["pattern_id"] for item in setup.redacting.violations} >= {
        "bearer_token",
        "aws_access_key_id",
    }
    print(f"EXPECTED_TRACE_ID={child_context.trace_id:032x}")
    print(f"EXPECTED_PARENT_ID={parent_context.span_id:016x}")
