"""Open Agent Assurance — minimal correlation service (COR-01)."""
# SPDX-License-Identifier: Apache-2.0

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
from .coverage import (
    OUT_OF_GATE_STATES,
    RECEIPTED_STATES,
    SCHEMA_VERSION,
    coverage,
)

__all__ = [
    "CORRELATION_STATES",
    "OUT_OF_GATE_STATES",
    "RECEIPTED_STATES",
    "SCHEMA_VERSION",
    "CorrelationConfig",
    "CorrelationRecord",
    "CorrelationResult",
    "ReceiptRecord",
    "TraceRecord",
    "coverage",
    "load_receipt_index",
    "reconcile",
    "sha256_file",
]
