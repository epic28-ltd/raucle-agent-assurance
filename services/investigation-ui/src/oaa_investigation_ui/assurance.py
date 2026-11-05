# SPDX-License-Identifier: Apache-2.0
"""OV-2: assurance packet exposed over HTTP on the investigation UI app.

Two routes delegate to the OV-1 packet generator's real code (imported by
file path, same pattern as the operator CLI), with the CLI's fail-visible
semantics carried into HTTP status codes:

- POST /assurance/packet -> packet JSON (application/json).
- GET  /assurance/summary -> packet HTML summary (textContent-only).

Failure mapping (nothing silent, nothing fabricated):
- missing evidence store -> 404 {"error": "..."} (the CLI's FAIL exit, 404-class);
- tampered / malformed store or bad declared refs -> 422 {"error": <named CLI error>}.
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys as _sys
from typing import Any, cast

# The generator is a flat module (no package identifier). Import by location
# exactly as scripts/rauckle-assurance-packet does.
_MODULE_PATH = pathlib.Path(__file__).resolve().parents[3] / "assurance_packet" / "packet.py"
_spec = importlib.util.spec_from_file_location("oaa_assurance_packet", _MODULE_PATH)
assert _spec is not None and _spec.loader is not None
_packet = importlib.util.module_from_spec(_spec)

_sys.modules["oaa_assurance_packet"] = _packet
_spec.loader.exec_module(_packet)

STORE_FILE = "evidence_store.jsonl"

# Declared-ref fields accepted in the POST body, each validated to its type.
_REF_FIELDS: dict[str, tuple[type, type]] = {
    "capability_refs": (list, str),
    "policy_proof_refs": (list, str),
    "risk_annotations": (list, str),
}

_DECLARED_LIST_ERROR = "{field} must be a list of strings"


def build_from_store(data_dir: pathlib.Path, refs: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compile the packet from this data dir's evidence store.

    Raises ValueError with the generator's own named message on any
    missing/tampered/malformed input; the HTTP layer maps that message.
    """
    store = pathlib.Path(data_dir).resolve() / STORE_FILE
    refs = refs or {}
    return cast(
        "dict[str, Any]",
        _packet.build_packet(
            store,
            capability_refs=refs.get("capability_refs"),
            policy_proof_refs=refs.get("policy_proof_refs"),
            governance_mapping=refs.get("governance_mapping"),
            risk_annotations=refs.get("risk_annotations"),
        ),
    )


def html_for(data_dir: pathlib.Path, refs: dict[str, Any] | None = None) -> str:
    """textContent-only packet HTML summary for this data dir."""
    return _packet.html_summary(build_from_store(data_dir, refs))


def body_refs(body: dict[str, Any] | None) -> dict[str, Any]:
    """Validated declared-refs subset of a POST body (422-named on bad type)."""
    if body is None:
        return {}
    unknown = sorted(set(body) - set(_REF_FIELDS) - {"governance_mapping"})
    if unknown:
        raise ValueError(f"unknown declared-ref field(s): {', '.join(unknown)}")
    out: dict[str, Any] = {}
    for field, (kind, item_kind) in _REF_FIELDS.items():
        value = body.get(field)
        if value is None:
            out[field] = None
            continue
        if not isinstance(value, kind) or not all(isinstance(v, item_kind) for v in value):
            raise ValueError(_DECLARED_LIST_ERROR.format(field=field))
        out[field] = value
    gov = body.get("governance_mapping")
    if gov is not None:
        if not isinstance(gov, dict) or not all(
            isinstance(k, str) and isinstance(v, list) and all(isinstance(i, str) for i in v)
            for k, v in gov.items()
        ):
            raise ValueError("governance_mapping must be a JSON object of framework -> id list")
        out["governance_mapping"] = gov
    return out
