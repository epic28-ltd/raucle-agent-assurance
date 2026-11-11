"""UI-01 offline receipt verification endpoint backend.

Wraps :func:`oaa_raucle_adapter.evidence_plane.classify` (raucle's own
ProvenanceVerifier) over the canonical ``{receipt_hash, jws}`` envelope line
from the read-only evidence store. raucle is an OPTIONAL dependency: when it
is not importable the result is an explicit ``unavailable`` state with the
reason — never a silently blank status and never a fabricated verdict.

JWS/secret handling: the canonical envelope line is passed to ``classify``
in-process only; the endpoint result contains index fields and verifier
output summary — never the JWS string.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os
import sys

from oaa_raucle_adapter.evidence_plane import classify


def _ensure_raucle_importable() -> None:
    """Allow an app-level runtime pointer to the pinned raucle worktree
    (``OAA_RAUCLE_SRC``); never a config-file or committed path."""
    src = os.environ.get("OAA_RAUCLE_SRC")
    if src and os.path.isdir(src) and src not in sys.path:
        sys.path.insert(0, src)


def verify_offline(envelope_line: str, registry) -> dict:
    """Classify one canonical envelope; explicit states for every outcome."""
    _ensure_raucle_importable()
    try:
        result = classify(envelope_line, registry)
    except ImportError as exc:
        return {
            "verification_status": "unavailable",
            "detail": f"offline verifier not available in this environment: {exc}",
            "checks_performed": [],
            "verifier_available": False,
            "checked_at": None,
            "verifier_version": None,
            "trust_policy_version": None,
        }
    except Exception as exc:
        return {
            "verification_status": "unavailable",
            "detail": f"offline verifier raised {type(exc).__name__}: {exc}",
            "checks_performed": [],
            "verifier_available": False,
            "checked_at": None,
            "verifier_version": None,
            "trust_policy_version": None,
        }
    return {
        "verification_status": result.verification_status,
        "detail": result.detail,
        "checks_performed": list(result.checks_performed),
        "verifier_available": True,
        "checked_at": result.checked_at,
        "verifier_version": result.verifier_version,
        "trust_policy_version": result.trust_policy_version,
    }
