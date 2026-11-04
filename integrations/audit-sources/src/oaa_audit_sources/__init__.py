# SPDX-License-Identifier: Apache-2.0
"""Open Agent Assurance — audit-source normalizers (K2, EPIC M).

Pure, offline normalizers for already-exported tool-side audit events
(AWS CloudTrail, GitHub audit log). NO network calls live in this package:
collectors/fetchers are deployment glue documented in
``docs/spikes/K2-findings.md`` and the package README.
"""

from .normalize import (
    CLOUDTRAIL_OP_MAP,
    AuditCandidate,
    AuditSourceConfig,
    normalize_cloudtrail,
    normalize_github,
)
from .reconcile import (
    CONFIDENCE_CLASSES,
    RECONCILIATION_STATES,
    ReceiptIndexRow,
    ReconciliationConventions,
    ReconciliationRecord,
    ReconciliationResult,
    reconcile,
)

__all__ = [
    "CLOUDTRAIL_OP_MAP",
    "CONFIDENCE_CLASSES",
    "RECONCILIATION_STATES",
    "AuditCandidate",
    "AuditSourceConfig",
    "ReceiptIndexRow",
    "ReconciliationConventions",
    "ReconciliationRecord",
    "ReconciliationResult",
    "normalize_cloudtrail",
    "normalize_github",
    "reconcile",
]
