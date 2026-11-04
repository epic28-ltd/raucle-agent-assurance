# SPDX-License-Identifier: Apache-2.0
"""PRIV-01 SDK-side redaction: deterministic span-attribute scrubbing.

A :class:`Redactor` loads a versioned pattern config and rewrites span
attribute values that match any pattern (or the entropy heuristic) into a
`[REDACTED:<class>|len=<n>]` token — a class tag plus the original length;
the matched secret itself never survives. Keys matching the allowlist globs
(the ``oaa.metadata.*`` namespace) pass through untouched.

Design invariants (companion ADRs): redaction happens at the SDK, before
export; a content-hash of a secret is NOT anonymisation (it remains a
derivative of the secret); the only retained datum is the original value
length, carried in the replacement token.

Detection is pattern- plus entropy-based, never semantic.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import pathlib
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import yaml

REDACTION_CONFIG_VERSION = 1
DEFAULT_CONFIG_PATH = pathlib.Path(__file__).resolve().parents[2] / "config" / "redaction.yaml"
REPLACEMENT_PREFIX = "[REDACTED"


@dataclass(frozen=True)
class RedactionViolation:
    """A detected sensitive value — carries metadata, never the matched value."""

    pattern_id: str
    privacy_class: str
    attr_key: str
    matched_length: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "class": self.privacy_class,
            "attr_key": self.attr_key,
            "matched_length": self.matched_length,
        }


@dataclass(frozen=True)
class RedactionConfig:
    """Parsed, versioned redaction config."""

    config_version: int
    patterns: tuple[dict[str, Any], ...]
    allowlist: tuple[str, ...]
    entropy: dict[str, Any]
    source_sha256: str
    source_path: str

    @property
    def config_sha256(self) -> str:
        """SHA-256 over the canonical config payload (not the file bytes)."""
        payload = json.dumps(
            {
                "config_version": self.config_version,
                "patterns": [dict(p) for p in self.patterns],
                "allowlist": list(self.allowlist),
                "entropy": self.entropy,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def shannon_entropy_per_char(value: str) -> float:
    """Deterministic Shannon entropy per character of ``value``."""
    if not value:
        return 0.0
    total = float(len(value))
    freqs = (value.count(ch) / total for ch in set(value))
    return -sum((f) * math.log2(f) for f in freqs if f > 0)


def _entropy_matches(value: str, spec: dict[str, Any]) -> bool:
    if len(value) < int(spec.get("min_length", 20)):
        return False
    if not spec.get("base64_charset_only", True):
        pass
    elif any(
        ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=_"
        for ch in value
    ):
        # charset gate: prose and kebab/dot-structured identifiers (oaa.run_id,
        # session ids, content-class tags) never look like opaque blobs; a
        # secret carrying an explicit dash would evade the entropy layer (the
        # pattern layer is the primary control) — declared limitation.
        return False
    return bool(shannon_entropy_per_char(value) >= float(spec.get("threshold_bits_per_char", 3.8)))


def replacement_token(privacy_class: str, original_length: int) -> str:
    """Deterministic replacement token: class tag + original length only."""
    return f"{REPLACEMENT_PREFIX}:{privacy_class}|len={original_length}]"


class Redactor:
    """Deterministic, versioned redactor for span-attribute values."""

    def __init__(self, config: RedactionConfig):
        self.config = config
        self._compiled: list[tuple[str, str, re.Pattern[str]]] = [
            (p["id"], p["class"], re.compile(p["match"])) for p in config.patterns
        ]
        self._entropy = dict(config.entropy)

    @classmethod
    def from_yaml(cls, path: str | pathlib.Path | None = None) -> Redactor:
        p = pathlib.Path(path) if path else DEFAULT_CONFIG_PATH
        data = p.read_bytes()
        raw = yaml.safe_load(data.decode("utf-8"))
        version = int(raw.get("config_version", 0))
        if version != REDACTION_CONFIG_VERSION:
            raise ValueError(
                f"unsupported redaction config_version {version}; expected "
                f"{REDACTION_CONFIG_VERSION}"
            )
        cfg = RedactionConfig(
            config_version=version,
            patterns=tuple(raw.get("patterns") or ()),
            allowlist=tuple(raw.get("allowlist") or ()),
            entropy=dict(raw.get("entropy_heuristic") or {}),
            source_sha256=hashlib.sha256(data).hexdigest(),
            source_path=str(p),
        )
        return cls(cfg)

    # -- detection helpers ------------------------------------------------
    def is_allowlisted(self, attr_key: str) -> bool:
        return any(fnmatch.fnmatchcase(attr_key, glob) for glob in self.config.allowlist)

    def scan_string(self, attr_key: str, value: str) -> list[RedactionViolation]:
        """Detect violations in one string value without rewriting it."""
        if self.is_allowlisted(attr_key):
            return []
        if value.startswith(REPLACEMENT_PREFIX):
            # an already-redacted token is not a live secret: scanning it
            # again would flag the marker (high-entropy-looking) and make
            # the collector quarantine clean payloads
            return []
        violations: list[RedactionViolation] = []
        for pattern_id, privacy_class, regex in self._compiled:
            m = regex.search(value)
            if m:
                violations.append(
                    RedactionViolation(
                        pattern_id=pattern_id,
                        privacy_class=privacy_class,
                        attr_key=attr_key,
                        matched_length=len(m.group(0)),
                    )
                )
        if (
            not violations
            and self._entropy.get("enabled")
            and _entropy_matches(value, self._entropy)
        ):
            violations.append(
                RedactionViolation(
                    pattern_id="entropy_heuristic",
                    privacy_class=self._entropy.get("class", "high_entropy"),
                    attr_key=attr_key,
                    matched_length=len(value),
                )
            )
        return violations

    # -- main API ---------------------------------------------------------
    def redact(
        self, span_attributes: dict[str, Any]
    ) -> tuple[dict[str, Any], list[RedactionViolation]]:
        """Redact a *copy* of a span-attribute mapping; the input is not mutated."""
        out: dict[str, Any] = {}
        violations: list[RedactionViolation] = []
        for key, value in span_attributes.items():
            if not isinstance(value, str) or self.is_allowlisted(key):
                out[key] = value
                continue
            sub_violations = self.scan_string(key, value)
            if not sub_violations:
                out[key] = value
                continue
            new = value
            for pattern_id, privacy_class, regex in self._compiled:
                new = regex.sub(
                    lambda m, _pid=pattern_id, _cls=privacy_class: replacement_token(
                        _cls, len(m.group(0))
                    ),
                    new,
                )
            # entropy-only hit: wholesale replacement of the whole value
            if all(v.pattern_id == "entropy_heuristic" for v in sub_violations):
                only = sub_violations[0]
                out[key] = replacement_token(only.privacy_class, len(value))
                violations.extend(sub_violations)
                continue
            out[key] = new
            violations.extend(sub_violations)
        return out, violations


@dataclass
class ScanReport:
    """Result of a collector-side batch re-scan (defence in depth)."""

    span_count: int
    violations: list[RedactionViolation] = field(default_factory=list)

    @property
    def clean(self) -> bool:
        return not self.violations

    def count_by_class(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for v in self.violations:
            counts[v.privacy_class] = counts.get(v.privacy_class, 0) + 1
        return dict(sorted(counts.items()))

    @property
    def violation_count(self) -> int:
        return len(self.violations)

    def as_dict(self) -> dict[str, Any]:
        return {
            "span_count": self.span_count,
            "violation_count": len(self.violations),
            "counts_by_class": self.count_by_class(),
            "clean": self.clean,
        }


def scan_batch(
    span_attribute_maps: Iterable[dict[str, Any]], redactor: Redactor | None = None
) -> ScanReport:
    """Re-scan a batch of span-attribute payloads for sensitive values.

    Collector-side defence in depth: runs over the payload about to be
    exported, independent of (and after) any SDK-side redaction. Violations
    are COUNTED, never echoed — a violation record carries only the attribute
    key and the value length, never the matched secret (the audit line that
    announces a leak must not itself contain the secret).
    """
    r = redactor or Redactor.from_yaml()
    violations: list[RedactionViolation] = []
    span_count = 0
    for attrs in span_attribute_maps:
        span_count += 1
        for key, value in attrs.items():
            if isinstance(value, str):
                violations.extend(r.scan_string(key, value))
    return ScanReport(span_count=span_count, violations=violations)


def quarantine(
    span_ids: Iterable[str],
    attribute_maps: Iterable[dict[str, Any]],
    report: ScanReport,
) -> list[str]:
    """Return (sorted) span ids whose attributes were flagged in ``report``.

    Quarantined spans are held back from export, counted on the report; the
    caller decides retention. Deterministic over the sorted output.
    """
    flagged_keys = {v.attr_key for v in report.violations}
    quarantined: list[str] = []
    for span_id, attrs in zip(span_ids, attribute_maps, strict=False):
        if any(k in flagged_keys for k in attrs):
            quarantined.append(span_id)
    return sorted(quarantined)


def scrub_span_attribute_map(
    attributes: dict[str, Any], redactor: Redactor
) -> tuple[dict[str, Any], list[RedactionViolation]]:
    """Scrub one span's attributes (alias over :meth:`Redactor.redact`)."""
    return redactor.redact(attributes)


__all__ = [
    "DEFAULT_CONFIG_PATH",
    "REDACTION_CONFIG_VERSION",
    "REPLACEMENT_PREFIX",
    "RedactionConfig",
    "RedactionViolation",
    "Redactor",
    "ScanReport",
    "quarantine",
    "replacement_token",
    "scan_batch",
    "scrub_span_attribute_map",
    "shannon_entropy_per_char",
]
