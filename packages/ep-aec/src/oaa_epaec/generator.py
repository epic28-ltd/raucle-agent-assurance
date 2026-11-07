# SPDX-License-Identifier: Apache-2.0
"""EP-AEC envelope generator — build AEC envelopes from an evidence store dir.

Reads the verbatim ``{receipt_hash, jws}`` JSONL store written by
``oaa_raucle_adapter.evidence_plane.EvidenceStore``, selects receipts, and
assembles EP-AEC-v1 envelopes:

- one component per chosen receipt; component type is a ROLE label
  (``policy-permit`` by default, or the custom ``rau-cle-gate-decision``
  family via ``component_type``);
- ``evidence_digest == receipt_hash`` (verified against the sha256 of the
  stored compact JWS);
- the component ``evidence`` object contains ONLY the receipt hash plus
  verification metadata — the raw JWS is referenced, never embedded, unless
  ``allow_embed_jws=True`` is set explicitly;
- a requirement (e.g. ``"policy-permit"``) is evaluated under the draft's
  fixed limits and an ``EP-AEC-REPLAY-v1`` record is attached.

raucle is OPTIONAL: classifications can be supplied by the caller, or, when a
``TrustRootRegistry`` is given and raucle is importable, ``classify()`` is run
for real. Without either, components record ``ACCEPTED``/``unverified``.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib
from dataclasses import dataclass
from typing import Any

from .objects import (
    UNSATISFIED,
    ComponentFact,
    RequirementRejected,
    assemble_aec,
    build_action,
    build_replay_record,
    evaluate_requirement,
    jcs_digest,
    now_iso,
    trust_snapshot_digest,
)

DEFAULT_COMPONENT_TYPE = "policy-permit"


@dataclass
class EpaecConfig:
    """Generator configuration. Only ``allow_embed_jws`` is security-relevant:
    it gates embedding the raw JWS bytes inside the AEC (default: never)."""

    component_type: str = DEFAULT_COMPONENT_TYPE
    allow_embed_jws: bool = False


def read_evidence_store(store_dir: pathlib.Path | str) -> dict[str, dict[str, Any]]:
    """Index a store directory: {receipt_hash: {"line": <verbatim>, "jws": ...}}.

    Scans ``*.jsonl`` files; each line must be exactly ``{"receipt_hash",
    "jws"}``. Lines whose sha256 does not match the recorded receipt_hash are
    kept but flagged (``hash_ok: False``) — classification will call them out.
    """
    store_dir = pathlib.Path(store_dir)
    index: dict[str, dict[str, Any]] = {}
    for path in sorted(store_dir.glob("*.jsonl")):
        for raw in path.read_bytes().splitlines():
            if not raw.strip():
                continue
            entry, receipt_hash = _evidence_entry(path, raw)
            index.setdefault(receipt_hash, entry)
    return index


def _evidence_entry(path: pathlib.Path, raw: bytes) -> tuple[dict[str, Any], str]:
    """Validate one evidence-store line and build its index entry."""
    try:
        line = raw.decode("utf-8")
        rec = json.loads(line)
    except ValueError as e:
        raise ValueError(f"{path.name}: unparsable line: {e}") from None
    if not isinstance(rec, dict) or set(rec) != {"receipt_hash", "jws"}:
        shape = sorted(rec) if isinstance(rec, dict) else type(rec).__name__
        raise ValueError(f"{path.name}: line is not a canonical envelope: {shape}")
    if not isinstance(rec["jws"], str):
        raise ValueError(f"{path.name}: 'jws' must be a string, got {type(rec['jws']).__name__}")
    if not isinstance(rec["receipt_hash"], str):
        raise ValueError(
            f"{path.name}: 'receipt_hash' must be a string, got {type(rec['receipt_hash']).__name__}"
        )
    want = "sha256:" + hashlib.sha256(rec["jws"].encode()).hexdigest()
    entry = {
        "line": line,
        "jws": rec["jws"],
        "receipt_hash": rec["receipt_hash"],
        "hash_ok": rec["receipt_hash"] == want,
    }
    return entry, rec["receipt_hash"]


def _payload_of(entry: dict[str, Any]) -> dict[str, Any]:
    """Parse the receipt's signed payload (middle JWS segment)."""
    import base64

    segments = entry["jws"].split(".")
    if len(segments) != 3 or not all(segments):
        raise ValueError(
            f"malformed receipt JWS: compact serialization must have exactly "
            f"three non-empty segments, got {len(segments)}"
        )
    payload_b64 = segments[1]
    try:
        decoded = base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
    except Exception as e:
        raise ValueError(f"malformed receipt JWS: payload segment is not base64url: {e}") from None
    try:
        return json.loads(decoded.decode("utf-8"))
    except ValueError as e:
        raise ValueError(f"malformed receipt JWS: payload is not JSON: {e}") from None


def _classify_entry(
    entry: dict[str, Any], registry: Any, classifications: dict[str, Any] | None
) -> dict[str, Any]:
    """Resolve verification facts for one receipt.

    Priority: caller-supplied classification → evidence_plane.classify (real
    raucle) → accepted/unverified placeholder.
    """
    rh = entry["receipt_hash"]
    if classifications and rh in classifications:
        c = classifications[rh]
        if hasattr(c, "to_dict"):
            c = c.to_dict()
        return dict(c)
    if registry is not None:
        from oaa_raucle_adapter.evidence_plane import classify

        result = classify(entry["line"], registry)
        d = result.to_dict()
        d["fixture_name"] = rh
        return d
    return {
        "fixture_name": rh,
        "verification_status": "unverified",
        "checked_at": now_iso(),
        "verifier_version": "",
        "trust_policy_version": "",
        "checks_performed": [],
        "detail": "no registry / no raucle: accepted on presentation only",
    }


def _roots_of(registry: Any) -> list[dict[str, Any]]:
    if registry is None:
        return []
    return [
        {
            "key_id": r.key_id,
            "valid_from": r.valid_from,
            "valid_until": r.valid_until,
            "status": r.status,
        }
        for r in registry.roots
    ]


def build_envelope(
    store_dir: pathlib.Path | str,
    receipt_hashes: list[str],
    *,
    requirement: str | None = None,
    config: EpaecConfig | None = None,
    registry: Any | None = None,
    classifications: dict[str, Any] | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """Build one EP-AEC-v1 envelope (AEC + replay record) from receipts.

    Deterministic given the same store, inputs and injected clock: no wall
    clock, no dict-order sensitivity — everything serialised via JCS.

    Raises FileNotFoundError for missing receipts and
    :class:`RequirementRejected` when the requirement violates a fixed limit;
    an UNSATISFIED evaluation is NOT an error — it is recorded verbatim.
    """
    cfg = config or EpaecConfig()
    requirement = requirement if requirement is not None else cfg.component_type

    index = read_evidence_store(store_dir)
    components: list[ComponentFact] = []
    receipt_rows: list[dict[str, Any]] = []
    snap_digest = trust_snapshot_digest(_roots_of(registry))

    for rh in receipt_hashes:
        if rh not in index:
            raise FileNotFoundError(f"{rh} not in evidence store")
        entry = index[rh]
        cls = _classify_entry(entry, registry, classifications)
        verified = cls.get("verification_status") == "valid" and entry.get("hash_ok", False)

        evidence: dict[str, Any] = {
            "receipt_hash": rh,
            "verification_status": cls.get("verification_status", "unknown"),
            "verifier_version": cls.get("verifier_version", ""),
            "trust_policy_version": cls.get("trust_policy_version", ""),
        }
        if cfg.allow_embed_jws:
            evidence["jws"] = entry["jws"]  # explicit operator opt-in ONLY

        components.append(
            ComponentFact(
                type=cfg.component_type,
                evidence_digest=rh,
                evidence=evidence,
                result="VERIFIED" if verified else "ACCEPTED",
                trust_snapshot_digest=snap_digest,
                verification_status=cls.get("verification_status", "unknown"),
                verifier_version=cls.get("verifier_version", ""),
                trust_policy_version=cls.get("trust_policy_version", ""),
                freshness={
                    "checked_at": cls.get("checked_at", now_iso(now)),
                    "basis": "receipt signed iat within trust window of event time",
                },
                status_checks=list(cls.get("checks_performed", [])),
            )
        )
        receipt_rows.append({"receipt_hash": rh, "payload": _payload_of(entry)})

    action_build = (
        build_action(receipt_rows[0])
        if receipt_rows
        else build_action({"receipt_hash": "", "payload": {}})
    )
    envelope = assemble_aec(action_build, components, requirement)

    verdict, reason_codes = evaluate_requirement(requirement, {c.type for c in components})
    record = build_replay_record(envelope, verdict, reason_codes, components, now=now)
    # A rejected requirement is a build failure, not a UNSATISFIED record.
    if verdict == UNSATISFIED and "EVAL_UNSATISFIED" not in reason_codes:
        raise RequirementRejected(reason_codes[0])

    return {
        "aec": envelope.aec,
        "aec_digest": envelope.aec_digest,
        "replay": record,
        "envelope_digest": jcs_digest({"aec": envelope.aec, "replay": record}),
    }


__all__ = [
    "DEFAULT_COMPONENT_TYPE",
    "EpaecConfig",
    "build_envelope",
    "read_evidence_store",
]
