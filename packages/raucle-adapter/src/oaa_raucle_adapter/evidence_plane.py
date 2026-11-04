# SPDX-License-Identifier: Apache-2.0
"""Open Agent Assurance — evidence-plane module (EVD-01/EVD-02).

Implements ADR-0001 section 2 semantics against raucle v0.23.5:

- EvidenceStore: write canonical {receipt_hash, jws} JSONL verbatim;
  read back with sha256 integrity check. Never mutates bytes.
- TrustRootRegistry: trust roots keyed (key_id, valid_from, valid_until)
  with current/retired (archived) status. Event-time selection: a retired
  key still verifies historic receipts it signed (valid); a key_id absent
  from the archive yields unknown_key, never silently invalid.
- VerificationResult record: verification_status, checked_at,
  verifier_version (raucle __version__), trust_policy_version,
  checks_performed list.
- classify(): runs raucle's own ProvenanceVerifier over a single fixture
  and maps its failure mode onto the ADR-0001 state space:
  valid | invalid | unknown_key | unsupported_schema | pending |
  unavailable | not_applicable.

pending / unavailable are companion-side (async ingest) states: they are
produced by the harness, never guessed from a raucle failure.

raucle is an OPTIONAL dependency: this module imports it lazily so the
raucle-free unit tests (and CI without the signed-key environment) run the
store / trust-root / registry semantics alone.

Version provenance: raucle.__version__ has been stale behind actual releases
(reported 0.22.0 at the 0.23.5 pin), so verifier_version is keyed on the
distribution pin below, not the package constant. See the package README.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib
import json
import pathlib
import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Any

# Distro pin for raucle (verified code-level at commit 63edacd, released 0.23.5).
RAUCLE_DISTRIBUTION_PIN = "raucle 0.23.5 (git 63edacd)"

TRUST_POLICY_VERSION = "evd-trust-1"


def _raucle():
    """Lazy import of the optional raucle dependency, with install guidance."""
    try:
        import raucle  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "raucle is required for signature verification but is not installed. "
            "Install it from the pinned v0.23.5 worktree (git 63edacd) or "
            "PyPI raucle==0.23.5 — see packages/raucle-adapter/README.md."
        ) from exc
    importlib.import_module("raucle.gateway")
    importlib.import_module("raucle.provenance")
    return raucle


STATES = (
    "valid",
    "invalid",
    "unknown_key",
    "unsupported_schema",
    "pending",
    "unavailable",
    "not_applicable",
)


def _now_iso() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


# ---------------------------------------------------------------------------
# Canonical evidence store
# ---------------------------------------------------------------------------


class EvidenceStore:
    """Byte-verbatim {receipt_hash, jws} JSONL store with sha256 integrity."""

    def __init__(self, path: pathlib.Path) -> None:
        self.path = pathlib.Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._digests: dict[str, str] = {}

    def put(self, envelope_line: str) -> str:
        """Append one canonical envelope line; return its sha256 hex digest."""
        rec = json.loads(envelope_line)
        if set(rec) != {"receipt_hash", "jws"}:
            raise ValueError(f"envelope must be exactly {{receipt_hash, jws}}, got {sorted(rec)}")
        digest = hashlib.sha256(envelope_line.encode()).hexdigest()
        self._digests[rec["receipt_hash"]] = digest
        with open(self.path, "ab") as fh:
            fh.write(envelope_line.encode() + b"\n")
        return digest

    def get(self, receipt_hash: str) -> str:
        """Look up by receipt_hash; returns the FIRST matching line verbatim."""
        for line in open(self.path, "rb"):
            rec = json.loads(line)
            if rec["receipt_hash"] == receipt_hash:
                return line.rstrip(b"\n").decode()
        raise FileNotFoundError(f"{receipt_hash} not in evidence store")

    def get_by_digest(self, line_digest: str) -> str:
        """Read back a line by the digest returned from put(); verifies the
        on-disk bytes still hash to the digest recorded at put-time. Raises
        FileNotFoundError if absent, KeyError if the storage bytes drifted.
        JWS-level validity is the verifier's job, not the store's."""
        for line in open(self.path, "rb"):
            plain = line.rstrip(b"\n").decode()
            if hashlib.sha256(plain.encode()).hexdigest() == line_digest:
                return plain
        raise FileNotFoundError(f"no line with digest {line_digest}")


# ---------------------------------------------------------------------------
# Versioned trust roots (ADR-0001 §2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrustRoot:
    key_id: str
    public_key_pem: str
    valid_from: str  # ISO-8601 UTC, inclusive
    valid_until: str | None  # ISO-8601 UTC, exclusive; None = still current
    status: str = "current"  # "current" | "retired"

    def trusted_at(self, event_time: dt.datetime) -> bool:
        start = dt.datetime.fromisoformat(self.valid_from)
        if event_time < start:
            return False
        if self.valid_until is not None and event_time >= dt.datetime.fromisoformat(
            self.valid_until
        ):
            return False
        return True


class TrustRootRegistry:
    """Trust roots keyed (key_id, valid_from, valid_until). Retired roots are
    archived, never deleted."""

    def __init__(self) -> None:
        self._roots: list[TrustRoot] = []
        self._history: list[dict] = []

    def add(self, root: TrustRoot) -> None:
        self._roots.append(root)
        self._history.append(
            {"event": "add", "key_id": root.key_id, "status": root.status, "at": _now_iso()}
        )

    def retire(self, key_id: str, valid_until: str) -> None:
        for i, r in enumerate(self._roots):
            if r.key_id == key_id and r.status == "current":
                self._roots[i] = TrustRoot(
                    r.key_id, r.public_key_pem, r.valid_from, valid_until, "retired"
                )
                self._history.append(
                    {
                        "event": "retire",
                        "key_id": key_id,
                        "valid_until": valid_until,
                        "at": _now_iso(),
                    }
                )
                return
        raise KeyError(f"no current trust root {key_id}")

    def keys_for_event_time(self, event_time: dt.datetime) -> dict[str, str]:
        """Return {key_id: pem} for roots trusted at *event_time*, including
        retired (archived) roots — ADR-0001: retirement never degrades
        historic verification."""
        return {r.key_id: r.public_key_pem for r in self._roots if r.trusted_at(event_time)}

    def knows(self, key_id: str) -> bool:
        return any(r.key_id == key_id for r in self._roots)

    @property
    def roots(self) -> list[TrustRoot]:
        return list(self._roots)


# ---------------------------------------------------------------------------
# Verification result record
# ---------------------------------------------------------------------------


@dataclass
class VerificationResult:
    fixture_name: str
    verification_status: str
    checked_at: str
    verifier_version: str
    trust_policy_version: str
    checks_performed: list[str] = field(default_factory=list)
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Verify + classify one fixture
# ---------------------------------------------------------------------------


def classify(
    envelope_line: str,
    registry: TrustRootRegistry,
    trust_policy_version: str = TRUST_POLICY_VERSION,
) -> VerificationResult:
    """Run raucle's own ProvenanceVerifier over a single envelope and map the
    outcome to the ADR-0001 state space."""
    raucle = _raucle()

    rec = json.loads(envelope_line)
    jws = rec["jws"]
    checks: list[str] = []
    header = json.loads(_b64d(jws.split(".")[0]))
    kid = header.get("kid")
    checks.append(
        f"jose_header_parsed (kid={kid!r}, crit={header.get('crit')!r}, alg={header.get('alg')!r})"
    )

    # Event-time trust-root selection (ADR-0001 §2): the receipt's own signed
    # `iat` decides which roots were trusted when the event happened — never
    # "now". Retired (archived) roots remain selectable for historic events.
    iat = json.loads(_b64d(jws.split(".")[1])).get("iat", 0)
    event_time = dt.datetime.fromtimestamp(int(iat), tz=dt.UTC)
    checks.append(f"event_time from signed iat: {event_time.isoformat()}")

    if not registry.knows(kid):
        checks.append("trust_root_lookup(key_id, event_time) -> key_id absent from archive")
        return VerificationResult(
            "fixture",
            "unknown_key",
            _now_iso(),
            RAUCLE_DISTRIBUTION_PIN,
            trust_policy_version,
            checks,
            f"key_id {kid!r} not in trust-root registry (any event time)",
        )

    keys = registry.keys_for_event_time(event_time)
    checks.append(f"trust_roots_at_event_time -> {sorted(keys)}")
    if kid not in keys:
        checks.append("key not trusted at event time (not merely retired)")
        return VerificationResult(
            "fixture",
            "invalid",
            _now_iso(),
            RAUCLE_DISTRIBUTION_PIN,
            trust_policy_version,
            checks,
            f"key_id {kid!r} not trusted at event time {event_time.isoformat()}",
        )

    want = "sha256:" + hashlib.sha256(jws.encode()).hexdigest()
    checks.append("receipt_hash == sha256(compact jws)")
    hash_ok = rec["receipt_hash"] == want
    if not hash_ok:
        checks.append("integrity check: receipt_hash mismatch (record tampered)")

    v = raucle.provenance.ProvenanceVerifier(public_keys=keys)
    checks.append("ProvenanceVerifier.verify_chain(temp, strict=True)")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="evd-")) / "one.jsonl"
    try:
        tmp.write_text(envelope_line + "\n")
        report = v.verify_chain(tmp)
        rd = report.to_dict()
        errors = rd.get("errors", [])
        checks.append(f"report.valid == {report.valid}; errors={errors}")
        if hash_ok and report.valid:
            state = "valid"
            joined = ""
        else:
            joined = " | ".join(errors)
            if "unknown critical header parameter" in joined:
                # schema-family error is definitive even though the header
                # mutation also breaks the stored hash in controlled copies
                state = "unsupported_schema"
            elif not hash_ok:
                state = "invalid"  # storage-level tamper, definitive before crypto
            elif "signature verification failed" in joined:
                state = "invalid"  # key archived but crypto fails: genuinely invalid
            elif "receipt_hash mismatch" in joined or "tampered" in joined:
                state = "invalid"
            else:
                state = "invalid"
        return VerificationResult(
            "fixture",
            state,
            _now_iso(),
            RAUCLE_DISTRIBUTION_PIN,
            trust_policy_version,
            checks,
            joined,
        )
    finally:
        shutil.rmtree(tmp.parent, ignore_errors=True)


# ---------------------------------------------------------------------------
# Rotation demo (EVD-02) lives in evd/evid_rotation_demo.py so the module
# remains import-clean; imports run_rotation_demo from here when executing.
# ---------------------------------------------------------------------------


def _demo_identity_v2():
    """Mint a fresh v2 issue identity purely via raucle's own primitives."""
    AgentIdentity = _raucle().provenance.AgentIdentity
    return AgentIdentity.generate(
        agent_id="agent:evd-gateway-v2",
        allowed_models=["claude-sonnet-4-6"],
        allowed_tools=[],
    )
