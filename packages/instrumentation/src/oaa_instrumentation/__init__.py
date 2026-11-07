# SPDX-License-Identifier: Apache-2.0
"""Open Agent Assurance — PRIV-01 instrumentation: SDK-side redaction and
collector-side defence-in-depth over span attributes, plus the OTel exporter
wrappers that install both layers.

Modules:
- :mod:`oaa_instrumentation.redaction` — deterministic, versioned redactor
  (``[REDACTED:<class>|len=<n>]`` replacement, NO key-tier metadata
  exemption since RED-031, entropy heuristic) and the collector batch
  scan/quarantine.
- :mod:`oaa_instrumentation.otel_processor` — ``RedactingSpanExporter``
  (redaction at the SDK, before export) and ``QuarantiningSpanExporter``
  (re-scan just before export; violations counted, never logged with content).
"""

from oaa_instrumentation.redaction import (
    REDACTION_CONFIG_VERSION,
    RedactionConfig,
    RedactionViolation,
    Redactor,
    ScanReport,
    quarantine,
    scan_batch,
)

__all__ = [
    "REDACTION_CONFIG_VERSION",
    "RedactionConfig",
    "RedactionViolation",
    "Redactor",
    "ScanReport",
    "quarantine",
    "scan_batch",
]
__version__ = "0.0.1.dev0"
