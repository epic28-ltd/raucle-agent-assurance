# SPDX-License-Identifier: Apache-2.0
"""EP-AEC-v1 objects — envelope, Action Object, JCS, evaluator, replay record.

Implements the subset of ``draft-schrock-ep-authorization-evidence-chain-08``
(4 Oct 2026) required by EPIC M K1:

- ``jcs()`` — RFC 8785 (JCS) canonical serialisation for the subset actually
  produced here: str / null / bool / numbers / arrays / objects, with keys
  sorted by UTF-16 code units and numbers serialised ECMAScript-style.
- ``build_action()`` / ``assemble_aec()`` — Action Object builder from a
  receipt index row and full AEC object assembly with sha256 digests computed
  over the JCS serialisation.
- ``evaluate_requirement()`` — deterministic AND/OR/NOT/parens evaluator over
  component-type atoms under the draft's FIXED limits:
  * 4096 bytes of requirement expression,
  * 256 tokens,
  * 32 paren nesting levels (level 33 is rejected),
  each violation rejected with a bounded reason code, never guessed around.
- ``build_replay_record()`` — ``EP-AEC-REPLAY-v1`` record with per-component
  normalised facts: component type, evidence_digest, native verifier profile
  digest, trust snapshot digest, VERIFIED/ACCEPTED result, CAID mapping
  verdict, and evaluator profile digest ``EP-AEC-EVALUATOR-08-v1``.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import math
import re
from dataclasses import dataclass, field
from typing import Any

EP_AEC_VERSION = "EP-AEC-v1"
REPLAY_VERSION = "EP-AEC-REPLAY-v1"
EVALUATOR_PROFILE_DIGEST = "EP-AEC-EVALUATOR-08-v1"

# Normalised facts carry a native-verifier PROFILE digest, not a live pin:
# the relying party pins the native verifier out-of-band; this digest only
# describes which verifier profile produced the recorded facts.
NATIVE_VERIFIER_PROFILE_DIGEST = "oaa-raucle-verifier:0.23.5:63edacd"

# Draft-fixed evaluator limits. These are constants of the profile, not knobs.
MAX_REQUIREMENT_BYTES = 4096
MAX_REQUIREMENT_TOKENS = 256
MAX_PAREN_DEPTH = 32

SATISFIED = "SATISFIED"
UNSATISFIED = "UNSATISFIED"
REJECTED = "REJECTED"

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def now_iso(now: dt.datetime | None = None) -> str:
    """UTC ISO-8601 (second precision). *now* is injectable for determinism."""
    if now is None:
        now = dt.datetime.now(dt.UTC)
    return now.astimezone(dt.UTC).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------------------
# JCS (RFC 8785) canonical serialisation — subset used by EP-AEC objects
# ---------------------------------------------------------------------------

_ESCAPES = {
    '"': '\\"',
    "\\": "\\\\",
    "\b": "\\b",
    "\t": "\\t",
    "\n": "\\n",
    "\f": "\\f",
    "\r": "\\r",
}

_SAFE_RE = re.compile(r"^[ !#-\[\]-~]*$")  # printable ASCII minus " and \


def _jcs_string(s: str) -> str:
    if _SAFE_RE.match(s):
        return '"' + s + '"'
    out = ['"']
    for ch in s:
        esc = _ESCAPES.get(ch)
        if esc:
            out.append(esc)
        elif ch < " " or "\x7f" <= ch <= "\x9f" or "\ud800" <= ch <= "\udfff" or ch == "\u2028":
            # C0/C1 controls, lone/bare surrogates and U+2028 are escaped so
            # the canonical form stays valid Unicode-JSON text.
            out.append("\\u" + format(ord(ch), "04x"))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _es6_number(value: float | int) -> str:
    """ECMAScript Number::toString(10) formatting, as RFC 8785 requires."""
    v = float(value)
    if not math.isfinite(v):
        raise ValueError("JCS numbers must be finite")
    if not v:
        return "0"  # collapses -0.0, per RFC 8785 sample data
    neg = v < 0
    from decimal import Decimal

    d = Decimal(repr(abs(v)))  # repr() gives the shortest round-trip form
    _, digits_raw, exp_raw = d.as_tuple()
    dig = "".join(str(int(x)) for x in digits_raw)
    # repr('2.0') carries a trailing zero; ES6 drops it. Each zero removed
    # shifts the decimal exponent by one to keep the value unchanged.
    exp = int(exp_raw)
    stripped = len(dig) - len(dig.rstrip("0"))
    if stripped == len(dig):
        return "0"
    if stripped:
        dig = dig[: len(dig) - stripped]
        exp += stripped
    k = len(dig)
    n = exp + k  # absolute value = 0.dig * 10^n
    if k <= n <= 21:
        s = dig + "0" * (n - k)
    elif 0 < n <= 21:
        s = dig[:n] + "." + dig[n:]
    elif -6 < n <= 0:
        s = "0." + "0" * (-n) + dig
    else:
        e = n - 1
        mant = dig[0] + ("." + dig[1:] if k > 1 else "")
        s = mant + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return ("-" + s) if neg else s


def _jcs_number(value: float | int) -> str:
    if isinstance(value, int):
        # I-JSON: integers must survive an IEEE-754 double round-trip.
        if -(2**53) <= value <= 2**53 and int(float(value)) == value:
            return _es6_number(value)
        raise ValueError(f"integer not exactly representable as a double: {value}")
    return _es6_number(value)


def _jcs_key_sort(key: str) -> bytes:
    """RFC 8785 key order: ascending UTF-16 code units. Comparing UTF-16-BE
    bytes is exactly comparing 16-bit code units left to right (little-endian
    byte-wise comparison would wrongly rank 0xD800-0xDFFF below U+2xxx)."""
    return key.encode("utf-16-be", "surrogatepass")


def jcs(value: Any) -> str:
    """RFC 8785 canonical JSON for the str/num/bool/null/array/object subset.

    Raises ValueError on non-finite numbers, integers losing double precision,
    and bare/lone surrogates (JCS §3.2.2.2 requires \\\\uXXXX escapes only for
    controls; lone surrogates are not serialisable I-JSON).
    """
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _jcs_string(value)
    if isinstance(value, (int, float)):
        return _jcs_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(jcs(item) for item in value) + "]"
    if isinstance(value, dict):
        for k in value:
            if not isinstance(k, str):
                raise TypeError(f"JCS object keys must be strings, got {type(k).__name__}")
        items = sorted(value.items(), key=lambda kv: _jcs_key_sort(kv[0]))
        inner = ",".join(_jcs_string(k) + ":" + jcs(v) for k, v in items)
        return "{" + inner + "}"
    raise TypeError(f"JCS subset does not cover {type(value).__name__}")


def sha256_hex(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")


def jcs_digest(value: Any) -> str:
    """sha256:<hex> over the JCS serialisation of *value*."""
    return sha256_hex(jcs(value).encode("utf-8"))


# ---------------------------------------------------------------------------
# Action Object (EP-AEC-v1) from a receipt index row
# ---------------------------------------------------------------------------

DESCRIPTIVE_SALT = b"ep-aec:descriptive-args:\x1f"


@dataclass
class ActionBuild:
    """Result of building the Action Object + digest + optional CAID."""

    action: dict[str, Any]
    action_digest: str
    action_caid: str | None
    caid_basis: str  # "descriptive" | "profile-pinned" | "omitted"
    args_digest_basis: str  # "x_gate-args" | "descriptive"


def build_action(receipt_row: dict[str, Any], *, include_caid: bool = True) -> ActionBuild:
    """Build the closed EP-AEC Action Object from one receipt index row.

    The row is the *parsed* receipt record: {"receipt_hash": ..., "payload":
    {...}} where payload is the receipt's signed JSON. Fields:

    - tool: from ``x_gate.tool`` (fallback ``operation``).
    - args_digest: sha256 over JCS of ``x_gate.args`` when the receipt carried
      it; otherwise a receipt-derived placeholder — sha256 over the receipt
      hash with a descriptive salt — marked ``basis: "descriptive"`` so the
      relying party never mistakes it for signed argument bytes.
    - principal: ``x_gate.agent_id`` (fallback ``agent_id``).
    - delegated_authority: ``x_gate.acting_for`` / ``approval_id`` when
      non-empty, else null.
    - trace_id: ``x_gate.trace_id`` (fallback ``trace_id``).
    """
    payload = receipt_row.get("payload") or {}
    gate = payload.get("x_gate") or {}
    receipt_hash = receipt_row.get("receipt_hash", "")

    tool = gate.get("tool") or payload.get("operation") or "unknown"
    principal = gate.get("agent_id") or payload.get("agent_id") or "unknown"
    trace_id = gate.get("trace_id") or payload.get("trace_id") or ""

    args = gate.get("args")
    if args is not None:
        args_digest = jcs_digest({"args": args})
        args_basis = "x_gate-args"
    else:
        args_digest = sha256_hex(DESCRIPTIVE_SALT + receipt_hash.encode("utf-8"))
        args_basis = "descriptive"

    delegated = gate.get("acting_for") or None
    approval_id = gate.get("approval_id") or None
    if delegated is None and approval_id is not None:
        delegated = {"approval_id": approval_id}
    elif delegated is not None:
        delegated = {"acting_for": delegated}

    action: dict[str, Any] = {
        "tool": tool,
        "args_digest": args_digest,
        "args_digest_basis": args_basis,
        "principal": principal,
        "delegated_authority": delegated,
        "trace_id": trace_id,
    }
    if not _SHA256_RE.match(action["args_digest"]):
        raise ValueError("args_digest must be sha256:<hex>")

    action_digest = jcs_digest(action)

    action_caid: str | None = None
    caid_basis = "omitted"
    if include_caid:
        # Descriptive CAID (draft profile-pinning NOT implemented in K1):
        # caid:1:<action-type>:<suite>:<digest-b64url> where the digest binds
        # the action_digest bytes. Relying parties must treat this as
        # descriptive only until CAID profiles land (see K1 findings doc).
        raw = bytes.fromhex(action_digest.split(":", 1)[1])
        action_caid = f"caid:1:{tool}:sha256:{sha256_b64url(raw)}"
        caid_basis = "descriptive"

    return ActionBuild(action, action_digest, action_caid, caid_basis, args_basis)


# ---------------------------------------------------------------------------
# AEC object assembly
# ---------------------------------------------------------------------------


@dataclass
class ComponentFact:
    """Normalised per-component facts carried into the replay record.

    ``evidence`` is the evidence object EMBEDDED in the component — by spec it
    contains ONLY the receipt hash plus verification metadata; the generator
    refuses to place the raw JWS here unless embedding is explicitly allowed.
    """

    type: str
    evidence_digest: str
    evidence: dict[str, Any]
    result: str  # VERIFIED | ACCEPTED
    native_verifier_profile_digest: str = NATIVE_VERIFIER_PROFILE_DIGEST
    trust_snapshot_digest: str = ""
    verification_status: str = "unverified"  # evidence-plane classification
    verifier_version: str = ""
    trust_policy_version: str = ""
    caid_mapping_verdict: str = "skipped_descriptive"
    freshness: dict[str, Any] = field(default_factory=dict)
    status_checks: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        if not _SHA256_RE.match(self.evidence_digest):
            raise ValueError(f"component evidence_digest not sha256 hex: {self.evidence_digest!r}")
        if self.result not in ("VERIFIED", "ACCEPTED"):
            raise ValueError(f"component result must be VERIFIED|ACCEPTED, got {self.result}")
        if "receipt_hash" not in self.evidence:
            raise ValueError("component evidence must carry receipt_hash")
        return {
            "type": self.type,
            "evidence_digest": self.evidence_digest,
            "evidence": dict(self.evidence),
            "native_verifier_profile_digest": self.native_verifier_profile_digest,
            "trust_snapshot_digest": self.trust_snapshot_digest,
            "result": self.result,
            "verification_status": self.verification_status,
            "verifier_version": self.verifier_version,
            "trust_policy_version": self.trust_policy_version,
            "caid_mapping_verdict": self.caid_mapping_verdict,
            "freshness": dict(self.freshness),
            "status_checks": list(self.status_checks),
        }


@dataclass
class AecEnvelope:
    """EP-AEC-v1 object plus its computed digests."""

    aec: dict[str, Any]
    aec_digest: str
    action_build: ActionBuild

    def canonical(self) -> str:
        """Byte-stable JCS serialisation of the AEC object."""
        return jcs(self.aec)


def assemble_aec(
    action_build: ActionBuild,
    components: list[ComponentFact],
    requirement: str,
) -> AecEnvelope:
    """Assemble the closed EP-AEC-v1 object.

    Component types are ROLE labels; the relying party pins the native
    verifier out-of-band, so no verifier is executed here. Component
    ``evidence`` objects come from the caller (generator) and must already be
    embedding-free unless the operator opted in.
    """
    comp_objs = [
        {
            "type": c.type,
            "evidence_digest": c.evidence_digest,
            "evidence": dict(c.evidence),
        }
        for c in components
    ]

    aec: dict[str, Any] = {
        "@version": EP_AEC_VERSION,
        "action": action_build.action,
        "action_digest": action_build.action_digest,
        "components": comp_objs,
        "requirement": requirement,
    }
    if action_build.action_caid is not None:
        aec["action_caid"] = action_build.action_caid
    digest = jcs_digest(aec)
    return AecEnvelope(aec, digest, action_build)


# ---------------------------------------------------------------------------
# Requirement-expression evaluator (draft-fixed limits)
# ---------------------------------------------------------------------------


class RequirementRejected(ValueError):
    """The requirement expression violated a fixed evaluator limit or the
    grammar; ``reason_code`` is the bounded, deterministic code."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        super().__init__(f"{reason_code}: {detail}" if detail else reason_code)
        self.reason_code = reason_code
        self.detail = detail


_ATOM_RE = re.compile(r"[A-Za-z0-9_.-]+")
_RESERVED = {"AND", "OR", "NOT"}


def _tokenize(req: str) -> list[str]:
    tokens: list[str] = []
    i = 0
    while i < len(req):
        ch = req[i]
        if ch.isspace():
            i += 1
            continue
        if ch in "()":
            tokens.append(ch)
            i += 1
            continue
        m = _ATOM_RE.match(req, i)
        if not m:
            raise RequirementRejected("EVAL_PARSE", f"unexpected character {ch!r} at offset {i}")
        word = m.group(0)
        tokens.append(word)
        i = m.end()
    return tokens


def evaluate_requirement(
    requirement: str, component_types: list[str] | set[str]
) -> tuple[str, list[str]]:
    """Evaluate *requirement* against the set of present component types.

    Grammar: ``expr := atom | 'NOT' expr | '(' expr ')' | expr ('AND'|'OR')
    expr`` with AND binding tighter than OR. Atoms are satisfied iff a
    component with that type is present. Returns ``(verdict, reason_codes)`` —
    SATISFIED / UNSATISFIED with bounded, sorted reason codes (missing atoms
    capped at 16, deterministic order) — or raises :class:`RequirementRejected`
    for any fixed-limit violation.
    """
    req = requirement or ""
    if len(req.encode("utf-8")) > MAX_REQUIREMENT_BYTES:
        raise RequirementRejected("EVAL_LIMIT_BYTES", f"> {MAX_REQUIREMENT_BYTES} bytes")
    tokens = _tokenize(req)
    if len(tokens) > MAX_REQUIREMENT_TOKENS:
        raise RequirementRejected("EVAL_LIMIT_TOKENS", f"> {MAX_REQUIREMENT_TOKENS} tokens")
    depth = 0
    max_depth = 0
    for tok in tokens:
        if tok == "(":
            depth += 1
            max_depth = max(max_depth, depth)
            if depth > MAX_PAREN_DEPTH:
                raise RequirementRejected("EVAL_LIMIT_NESTING", f"> {MAX_PAREN_DEPTH} paren levels")
        elif tok == ")":
            depth -= 1
        if depth < 0:
            raise RequirementRejected("EVAL_PARSE", "unbalanced ')'")
    if depth != 0:
        raise RequirementRejected("EVAL_PARSE", "unbalanced '('")

    # Recursive-descent evaluation, single pass, deterministic.
    present = set(component_types)
    pos = 0
    missing: set[str] = set()

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def parse_or() -> bool:
        nonlocal pos
        val = parse_and()
        while peek() == "OR":
            pos += 1
            val = parse_and() or val
        return val

    def parse_and() -> bool:
        nonlocal pos
        val = parse_unary()
        while peek() == "AND":
            pos += 1
            val = parse_unary() and val
        return val

    def parse_unary() -> bool:
        nonlocal pos
        tok = peek()
        if tok is None:
            raise RequirementRejected("EVAL_PARSE", "unexpected end of expression")
        if tok == "NOT":
            pos += 1
            return not parse_unary()
        if tok == "(":
            pos += 1
            val = parse_or()
            if peek() != ")":
                raise RequirementRejected("EVAL_PARSE", "expected ')'")
            pos += 1
            return val
        if tok == ")" or tok in ("AND", "OR"):
            raise RequirementRejected("EVAL_PARSE", f"unexpected token {tok!r}")
        pos += 1
        if tok in _RESERVED:
            raise RequirementRejected("EVAL_PARSE", f"reserved word used as atom: {tok!r}")
        ok = tok in present
        if not ok:
            missing.add(tok)
        return ok

    try:
        verdict_bool = parse_or()
    except RecursionError as exc:  # pathological nesting beyond the depth cap
        raise RequirementRejected("EVAL_PARSE", "evaluation recursed") from exc
    if pos != len(tokens):
        raise RequirementRejected("EVAL_PARSE", f"trailing tokens from offset {pos}")

    if verdict_bool:
        return SATISFIED, ["EVAL_SATISFIED"]
    codes = [f"EVAL_UNSATISFIED_ATOM:{name}" for name in sorted(missing)[:16]]
    if len(missing) > 16:
        codes.append("EVAL_UNSATISFIED_ATOMS_TRUNCATED")
    codes.append("EVAL_UNSATISFIED")
    return UNSATISFIED, codes


# ---------------------------------------------------------------------------
# EP-AEC-REPLAY-v1 replay record
# ---------------------------------------------------------------------------


def build_replay_record(
    envelope: AecEnvelope,
    verdict: str,
    reason_codes: list[str],
    component_facts: list[ComponentFact],
    *,
    now: dt.datetime | None = None,
    rejected: bool = False,
) -> dict[str, Any]:
    """Assemble the EP-AEC-REPLAY-v1 record from the envelope + facts.

    Normalised facts per component: type, evidence_digest, native verifier
    profile digest, trust snapshot digest, VERIFIED/ACCEPTED result, CAID
    mapping verdict, freshness/status results. The evaluator profile digest is
    fixed at ``EP-AEC-EVALUATOR-08-v1``.
    """
    evaluated_at = now_iso(now)
    record: dict[str, Any] = {
        "@version": REPLAY_VERSION,
        "aec_digest": envelope.aec_digest,
        "verdict": REJECTED if rejected else verdict,
        "reason_codes": list(reason_codes),
        "requirement": envelope.aec["requirement"],
        "evaluated_at": evaluated_at,
        "evaluator_profile_digest": EVALUATOR_PROFILE_DIGEST,
        "evaluator_limits": {
            "max_requirement_bytes": MAX_REQUIREMENT_BYTES,
            "max_requirement_tokens": MAX_REQUIREMENT_TOKENS,
            "max_paren_depth": MAX_PAREN_DEPTH,
        },
        "components": [c.to_dict() for c in component_facts],
    }
    return record


def replay_record_digest(record: dict[str, Any]) -> str:
    """Digest over the JCS serialisation of the replay record (sans its own
    digest field, which is never part of the record itself)."""
    return jcs_digest(record)


def trust_snapshot_digest(roots: list[dict[str, Any]] | None) -> str:
    """Digest over the JCS serialisation of the trust snapshot — the sorted
    (key_id, valid_from, valid_until, status) root set from the evidence
    plane's TrustRootRegistry, digest of the empty snapshot when absent."""
    snap = sorted(
        roots or [],
        key=lambda r: (r.get("key_id", ""), r.get("valid_from", "")),
    )
    return jcs_digest({"keys": snap})


# Backwards-friendly alias used by the generator.
def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


__all__ = [
    "EP_AEC_VERSION",
    "EVALUATOR_PROFILE_DIGEST",
    "MAX_PAREN_DEPTH",
    "MAX_REQUIREMENT_BYTES",
    "MAX_REQUIREMENT_TOKENS",
    "NATIVE_VERIFIER_PROFILE_DIGEST",
    "REJECTED",
    "REPLAY_VERSION",
    "SATISFIED",
    "UNSATISFIED",
    "ActionBuild",
    "AecEnvelope",
    "ComponentFact",
    "RequirementRejected",
    "assemble_aec",
    "build_action",
    "build_replay_record",
    "evaluate_requirement",
    "jcs",
    "jcs_digest",
    "now_iso",
    "replay_record_digest",
    "trust_snapshot_digest",
]
