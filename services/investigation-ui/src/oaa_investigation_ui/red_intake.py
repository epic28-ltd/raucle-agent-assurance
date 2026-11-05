# SPDX-License-Identifier: Apache-2.0
"""Red findings intake (RED-INTEGRATION): the future Raucle Agent Red
product posts its findings JSONL here at the end of every run.

Contract (full write-up in docs/spikes/RED-INTEGRATION-findings.md):

- wire format: the POST /api/findings/ingest body is either a JSON array
  of finding objects, an object ``{"findings": [...]}``, or JSONL text
  (one finding object per line) — exactly the shape the red corpora
  write at ``corpora/findings.jsonl``;
- per finding, validated fields::

    finding_id    deterministic UUID5 (version-5, RFC-4122 variant)
    rule          RED-xxx
    rule_label    display label
    severity      info | low | medium | high | critical
    confidence    low | medium | high
    evidence_ref  {kind, value, sha256}  (sha256 = 64 hex chars)
    explanation   what was observed (NO intent attribution)
    suggested_action  free text
    suite         suite name

- evidence integrity: when ``evidence_ref.value`` is a local file path
  that exists, the file's sha256 is re-computed at ingest and must match
  ``evidence_ref.sha256``; non-path references (e.g. audit_row hashes
  where value == sha256) are format-checked only;
- storage: accepted findings merge into the sidecar index
  ``red_findings.json`` inside the data dir (never the canonical
  evidence store), the same sidecar pattern as ``triage_state.json``;
- idempotency by ``finding_id``: re-posting a run replaces the same-id
  entries (same deterministic ids ⇒ re-ingesting is a no-op for already
  present findings).

Severity → risk-lens mapping (documented in counting.py): every ingested
red finding starts as an untriaged (New) board item; its board risk lens
folds by severity: critical/high → needs_investigation, medium/low →
unproven, info → unproven (an info finding attests only that a probe ran
and its detection logic confirmed — a claim the board's human has not
judged, so nothing lands in coverage_gaps).

Per-rule guidance: the red rules (RED-xxx) are not in the assurance G
rule map, so every red board row carries a guidance string from here —
the per-rule text when known, else the generic fallback.
"""

from __future__ import annotations

import hashlib
import json
import pathlib
import re
import uuid

from .counting import now_iso

RED_SOURCE = "red-mvp"

RED_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")
RED_SEVERITIES = frozenset(RED_SEVERITY_ORDER)
RED_CONFIDENCE = frozenset({"low", "medium", "high"})

# Severity → board risk lens (documented at module level; see counting.py).
RED_LENS_BY_SEVERITY = {
    # Values use the board's own short lens vocabulary ("needs", "unproven",
    # "gaps"); counting.py folds them by severity for the KPI headline, so
    # column filters and KPIs always agree on the same strings.
    "critical": "needs",
    "high": "needs",
    "medium": "unproven",
    "low": "unproven",
    "info": "unproven",
}

REQUIRED_FIELDS = (
    "finding_id",
    "rule",
    "rule_label",
    "severity",
    "confidence",
    "evidence_ref",
    "explanation",
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RULE_RE = re.compile(r"^RED-\d+$")

_generic_red_guidance = (
    "Red probe finding (RED suite). Read the explanation for what the probe "
    "observed, then re-run the cited suite against the affected run and check "
    "the referenced evidence; the finding does not attribute intent."
)
# Guidance for rules the red corpora emit; anything unknown falls back above.
RED_RULE_GUIDANCE = {
    "RED-003": (
        "Tamper/attribution probe result. If severity is medium or above, "
        "re-verify the cited receipt set offline and check whether the tampered "
        "item reached the findings board or stayed contained."
    ),
    "RED-004": (
        "Forge-resistance probe result. A PASS row is a confirmed detection; "
        "still confirm the forged input never produced a signed artifact."
    ),
    "RED-006": (
        "Gate-bypass probe result. Any non-info finding here means an attempt "
        "evaded or degraded the gate: pull the gate log for the window and "
        "confirm the decision trail is receipted."
    ),
    "RED-007": (
        "Prompt/harness probe against the agent. If medium or above, treat the "
        "cited trace as suspect and re-run the window with the probe payload "
        "removed."
    ),
    "RED-009": (
        "Receipt-replay probe result. Replay attributable means detection "
        "worked; monitor the receipt index for duplicate hashes afterwards."
    ),
    "RED-011": (
        "Evidence-plane probe result. Check the referenced store/index rows "
        "directly and confirm the invariant the suite asserts still holds."
    ),
}


def red_guidance(rule: str) -> str:
    return RED_RULE_GUIDANCE.get(rule, _generic_red_guidance)


# ------------------------------------------------------------------ sidecar
def red_sidecar_path(data_dir: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(data_dir) / "red_findings.json"


def load_red_findings(data_dir: pathlib.Path) -> list[dict]:
    """Ingested red findings from the sidecar (empty list when none)."""
    path = red_sidecar_path(data_dir)
    if not path.is_file():
        return []
    try:
        doc = json.loads(path.read_text())
        return doc.get("findings", []) if isinstance(doc, dict) else []
    except (OSError, ValueError):
        return []


def ingest_red_findings(data_dir: pathlib.Path, findings: list[dict]) -> dict:
    """Validate + merge (idempotent by finding_id) into the sidecar index."""
    path = red_sidecar_path(data_dir)
    try:
        existing: dict[str, dict] = {}
        for old in load_red_findings(data_dir):
            existing[old["finding_id"]] = old
    except (KeyError, TypeError):
        existing = {}
    replaced = 0
    for raw in findings:
        stored = _normalize(raw)
        if stored["finding_id"] in existing:
            replaced += 1
        existing[stored["finding_id"]] = stored
    merged = sorted(existing.values(), key=lambda f: (f["ingested_at"], f["finding_id"]))
    path.write_text(
        json.dumps({"source": RED_SOURCE, "findings": merged}, indent=2, sort_keys=True)
    )
    return {
        "total": len(merged),
        "accepted": len(findings),
        "replaced": replaced,
        "new": len(findings) - replaced,
    }


# ------------------------------------------------------------------ parser
def _payload_findings(payload) -> list[dict] | None:
    """Findings from a pre-parsed body, when the shape is recognised."""
    if isinstance(payload, dict) and isinstance(payload.get("findings"), list):
        return payload["findings"]
    if isinstance(payload, list):
        return payload
    return None


def _jsonl_rows(text: str) -> list[dict]:
    """JSONL: one object per line; blank lines and # comments ignored."""
    out = []
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        out.append(json.loads(ln))
    return out


def _shaped_findings(parsed) -> list[dict]:
    """Findings from a parsed body, unwrapping the ``findings`` key."""
    if isinstance(parsed, dict) and isinstance(parsed.get("findings"), list):
        return parsed["findings"]
    if isinstance(parsed, list):
        return parsed
    return [parsed]


def parse_findings_body(body_text: str, payload=None) -> list[dict]:
    """Accept a JSON array, an ``{"findings": [...]}`` object or JSONL text."""
    if payload is not None:
        rows = _payload_findings(payload)
        if rows is not None:
            return rows
    text = (body_text or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
    except ValueError:
        return _jsonl_rows(text)
    return _shaped_findings(parsed)


# ---------------------------------------------------------------- validator
def validate_red_finding(raw) -> dict:
    """Schema-validate one red finding; returns it unchanged, or raises."""
    if not isinstance(raw, dict):
        raise ValueError("each finding must be a JSON object")
    missing = [k for k in REQUIRED_FIELDS if k not in raw]
    if missing:
        raise ValueError(f"missing field(s): {', '.join(missing)}")
    _validate_finding_id(raw)
    if not _RULE_RE.match(str(raw["rule"])):
        raise ValueError(f"rule must match RED-xxx: {raw['rule']}")
    if raw["severity"] not in RED_SEVERITIES:
        raise ValueError(f"severity not in {sorted(RED_SEVERITIES)}: {raw['severity']}")
    if raw["confidence"] not in RED_CONFIDENCE:
        raise ValueError(f"confidence not in {sorted(RED_CONFIDENCE)}: {raw['confidence']}")
    _validate_evidence_ref(raw)
    return raw


def _validate_finding_id(raw: dict) -> None:
    """finding_id must be a deterministic UUID5."""
    try:
        uid = uuid.UUID(str(raw["finding_id"]))
    except ValueError as exc:
        raise ValueError(f"finding_id is not a valid UUID: {raw['finding_id']}") from exc
    if uid.variant != uuid.RFC_4122 or uid.version != 5:
        raise ValueError(f"finding_id is not UUID5: {raw['finding_id']}")


def _validate_evidence_ref(raw: dict) -> None:
    """evidence_ref requires kind/value/sha256; a local path reference is
    re-hashed at ingest."""
    ref = raw["evidence_ref"]
    if not isinstance(ref, dict) or not {"kind", "value", "sha256"} <= set(ref):
        raise ValueError("evidence_ref requires kind, value, sha256")
    if not _SHA256_RE.match(str(ref.get("sha256", ""))):
        raise ValueError("evidence_ref.sha256 must be 64 hex chars")
    if not str(ref["value"]) or not str(raw["explanation"]):
        raise ValueError("evidence_ref.value and explanation must be non-empty")
    value = pathlib.Path(str(ref["value"]))
    if value.is_file():
        digest = hashlib.sha256(value.read_bytes()).hexdigest()
        if digest != ref["sha256"]:
            raise ValueError(
                f"evidence integrity mismatch for {value}: sha256 {digest} != {ref['sha256']}"
            )


def _normalize(raw: dict) -> dict:
    validate_red_finding(raw)
    return {
        "finding_id": raw["finding_id"],
        "rule": raw["rule"],
        "rule_label": raw["rule_label"],
        "severity": raw["severity"],
        "confidence": raw["confidence"],
        "evidence_ref": dict(raw["evidence_ref"]),
        "explanation": raw["explanation"],
        "suggested_action": raw.get("suggested_action", ""),
        "suite": raw.get("suite", ""),
        "ingested_at": now_iso(),
    }


# ------------------------------------------------------------- board merge
def red_board_finding(stored: dict) -> dict:
    """Project a sidecar finding onto the findings-board finding shape."""
    return {
        "id": "red-" + stored["finding_id"],
        "rule_id": stored["rule"],
        "rule_version": "red",
        "severity": stored["severity"],
        "confidence": stored["confidence"],
        "evidence_refs": [stored["evidence_ref"]["value"], stored["evidence_ref"]["sha256"]],
        "explanation": stored["explanation"],
        "subject": stored["rule_label"],
        "suppressed": False,
        "suppression_reason": None,
        "detected_at": stored["ingested_at"],
        "run_id": None,
        "source": RED_SOURCE,
        "guidance": red_guidance(stored["rule"]),
    }
