# SPDX-License-Identifier: Apache-2.0
"""PRIV-01 OTel integration: SDK-side redaction + collector-side quarantine.

Two layers, both deterministic:

* ``RedactingSpanExporter`` — an SDK-side exporter wrapper that scrubs every
  span's attributes through the versioned :class:`Redactor` just before the
  delegate exporter is called. Redaction happens at the SDK, before export.
* ``QuarantiningSpanExporter`` — collector-side defence in depth: re-scans
  the (already scrubbed) batch right before export; any span whose
  attributes still carry a pattern/entropy hit is held back from the
  delegate export and COUNTED. A violation record never contains the
  matched secret.
"""

from __future__ import annotations

from typing import Any

from opentelemetry.sdk.trace import ReadableSpan
from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult

from oaa_instrumentation.redaction import Redactor, ScanReport, scan_batch


def span_attribute_map(span: ReadableSpan) -> dict[str, Any]:
    """Snapshot of a span's attributes as a plain dict (no OTEL types)."""
    return {k: v.value if hasattr(v, "value") else v for k, v in span.attributes.items()}


class _CountedExporter(SpanExporter):
    """Base wrapper: keeps a delegate exporter plus its shutdown/force state."""

    def __init__(self, delegate: SpanExporter):
        self._delegate = delegate
        self.violations: list[dict[str, Any]] = []
        self.last_scan: ScanReport | None = None

    def shutdown(self) -> None:  # pragma: no cover - trivial
        self._delegate.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._delegate.force_flush(timeout_millis)


class RedactingSpanExporter(_CountedExporter):
    """SDK-side layer: scrub attributes on export, then delegate.

    Mutates the span's internal attribute mapping (the SDK hands us the
    read-only ``ReadableSpan`` whose export path will reuse the same dict,
    so rewriting ``_attributes`` guarantees what the delegate serialises has
    already been redacted). The original attribute dict is snapshotted first
    so violations can be counted deterministically against the RAW values
    without ever retaining the secrets themselves.
    """

    def __init__(self, delegate: SpanExporter, redactor: Redactor | None = None):
        super().__init__(delegate)
        self.redactor = redactor or Redactor.from_yaml()

    def export(self, spans: Any) -> SpanExportResult:
        for span in spans:
            raw = span_attribute_map(span)
            scrubbed, violations = self.redactor.redact(raw)
            # violation records: pattern/class/key/lengths only — no secrets
            self.violations.extend(v.as_dict() for v in violations)
            span._attributes = scrubbed
        return self._delegate.export(spans)


class QuarantiningSpanExporter(_CountedExporter):
    """Collector-side layer: re-scan the batch immediately before export.

    Runs ``scan_batch`` over the spans it receives; spans flagged by the scan
    are held back (quarantined, counted) and never reach the delegate.
    Zero-violation batches are passed through untouched.
    """

    def __init__(self, delegate: SpanExporter, redactor: Redactor | None = None):
        super().__init__(delegate)
        self.redactor = redactor or Redactor.from_yaml()
        self.quarantined_span_ids: list[int] = []

    def export(self, spans: Any) -> SpanExportResult:
        spans = list(spans)
        maps = [span_attribute_map(s) for s in spans]
        report = scan_batch(maps, self.redactor)
        self.last_scan = report
        keep: list[ReadableSpan] = []
        for span, attrs in zip(spans, maps, strict=False):
            if any(v.attr_key in attrs for v in report.violations):
                self.quarantined_span_ids.append(getattr(span.context, "span_id", 0))
            else:
                keep.append(span)
        if not keep:
            return SpanExportResult.SUCCESS
        return self._delegate.export(keep)

    def summary(self) -> dict[str, Any]:
        scan = self.last_scan.as_dict() if self.last_scan else {}
        return {
            **scan,
            "quarantined_span_count": len(self.quarantined_span_ids),
        }


__all__ = [
    "QuarantiningSpanExporter",
    "RedactingSpanExporter",
    "span_attribute_map",
]
