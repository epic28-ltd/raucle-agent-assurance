# SPDX-License-Identifier: Apache-2.0
"""Open Agent Assurance — raucle evidence adapter.

Core module: :mod:`oaa_raucle_adapter.evidence_plane` (EvidenceStore,
TrustRootRegistry, classify) per ADR-0001. Fixture generation:
:mod:`oaa_raucle_adapter.fixture_gen`.
"""

from oaa_raucle_adapter.evidence_plane import (
    RAUCLE_DISTRIBUTION_PIN,
    EvidenceStore,
    TrustRoot,
    TrustRootRegistry,
    VerificationResult,
    classify,
)

__all__ = [
    "RAUCLE_DISTRIBUTION_PIN",
    "EvidenceStore",
    "TrustRoot",
    "TrustRootRegistry",
    "VerificationResult",
    "classify",
]
__version__ = "0.0.1.dev0"
