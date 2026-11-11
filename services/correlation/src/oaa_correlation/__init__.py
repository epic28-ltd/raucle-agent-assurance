"""Open Agent Assurance — minimal correlation service (COR-01)."""
# SPDX-License-Identifier: FSL-1.1-ALv2

from .core import (
    CORRELATION_STATES,
    CorrelationConfig,
    CorrelationRecord,
    CorrelationResult,
    ReceiptRecord,
    TraceRecord,
    load_receipt_index,
    reconcile,
    sha256_file,
)

__all__ = [
    "CORRELATION_STATES",
    "CorrelationConfig",
    "CorrelationRecord",
    "CorrelationResult",
    "ReceiptRecord",
    "TraceRecord",
    "load_receipt_index",
    "reconcile",
    "sha256_file",
]
