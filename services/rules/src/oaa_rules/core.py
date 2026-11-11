"""Open Agent Assurance — deterministic security rules engine (RULE-01).

Implements SEC-001..SEC-011 over INDEX-PLANE records only:

- correlation results (ADR-0002 states),
- verification results (ADR-0001 states),
- tool-side audit records (vantage A),
- custody / credential-lease events (vantage C),
- producer-identity / ingest events,
- gate-receipt index rows (receipt_hash + decision only — never canonical
  receipt bytes).

Bypass rules (SEC-009) never consume trace-only content: an absence of a
*trace* record is never a bypass signal (ADR-0004 §Decision 1). An absence of
a *tool-side* corroborating receipt is.

Findings state the observed discrepancy and a confidence class — never intent
(ADR-0004 §4; plan non-goals). Suppressed findings are RETAINED, not dropped:
the finding keeps all fields with ``suppression_reason`` filled, so the
suppression is documented where a reviewer will see it.

Config is a versioned YAML file (``services/rules/config/rules.yaml``,
schema v1 — see ``schemas/rules-config.schema.json``). All thresholds and the
default privileged-tool registry are config-driven; every rule is
deterministic and table-driven testable.
"""
# SPDX-License-Identifier: FSL-1.1-ALv2

from __future__ import annotations

import datetime as dt
import itertools
import re
from collections.abc import Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Protocol

SEVERITIES = ("critical", "high", "medium", "low", "info")
CONFIDENCES = ("high", "medium", "low")

EVENT_KINDS = (
    "correlation",  # ADR-0002 states, one per record (index rows only)
    "verification",  # ADR-0001 states (status in `state`)
    "tool_audit",  # vantage A: what actually executed
    "custody",  # vantage C: leases and credential use
    "identity",  # producer authentication / rotation chain
    "ingest",  # evidence-ingest coverage events (e.g. sink unavailable)
)

CORRELATED_RECEIPT_STATES = frozenset({"matched", "duplicate", "ambiguous", "late_arrival"})

# ---------------------------------------------------------------- events ----


@dataclass(frozen=True)
class Event:
    """One index-plane record handed to the rules engine.

    Canonical receipt bytes are never carried here — only index fields
    (receipt_hash, decision, event time). Telemetry index content may appear
    in ``content`` for SEC-008 pattern checks; findings NEVER carry it.
    Synthetic index rows (tests) set ``synthetic=True``.
    """

    kind: str
    at: dt.datetime
    ref: str | None = None  # evidence reference id (goes into findings)
    agent_id: str | None = None
    tool: str | None = None
    application: str | None = None
    trace_id: str | None = None
    receipt_hash: str | None = None
    state: str | None = None  # correlation state or verification status
    decision: str | None = None  # allow / deny (gate receipt index row)
    outcome: str | None = None  # tool-audit outcome (e.g. success/failure)
    privileged: bool | None = None
    credential_id: str | None = None
    action: str | None = None  # custody action: lease_issued | use
    lease_id: str | None = None
    release_id: str | None = None
    chain_seq: int | None = None
    producer_id: str | None = None
    authenticated: bool | None = None
    content: str | None = None  # telemetry index text (patterns only)
    synthetic: bool = False

    def __post_init__(self) -> None:
        if self.kind not in EVENT_KINDS:
            raise ValueError(f"unknown event kind: {self.kind!r}")
        object.__setattr__(self, "at", _as_utc(self.at))


def _as_utc(at: dt.datetime) -> dt.datetime:
    if at.tzinfo is None:
        return at.replace(tzinfo=dt.UTC)
    return at.astimezone(dt.UTC)


# --------------------------------------------------------------- findings ---


@dataclass(frozen=True)
class Finding:
    """One rule verdict. States discrepancy + confidence, never intent."""

    rule_id: str
    rule_version: str
    severity: str
    confidence: str
    evidence_refs: tuple[str, ...]
    explanation: str
    subject: str | None = None  # agent / tool / trace the finding is about
    suppression_reason: str | None = None  # set ⇒ documented, retained


# ----------------------------------------------------------------- config ---


@dataclass(frozen=True)
class Suppression:
    """Documented, versioned suppression. Matches narrowly (all set fields)."""

    rule_id: str
    reason: str
    agent_id: str | None = None
    tool: str | None = None
    trace_id: str | None = None
    subject: str | None = None
    credential_id: str | None = None
    release_id: str | None = None
    application: str | None = None

    def applies(self, rule_id: str, subject: str | None, ev: Event | None) -> bool:
        if rule_id != self.rule_id:
            return False
        ev_fields: dict[str, str | None] = (
            {}
            if ev is None
            else {
                "agent_id": ev.agent_id,
                "tool": ev.tool,
                "trace_id": ev.trace_id,
                "credential_id": ev.credential_id,
                "release_id": ev.release_id,
                "application": ev.application,
            }
        )
        for name in (
            "agent_id",
            "tool",
            "trace_id",
            "credential_id",
            "release_id",
            "application",
        ):
            want = getattr(self, name)
            if want is not None and ev_fields.get(name) != want:
                return False
        return not (self.subject is not None and subject != self.subject)


@dataclass(frozen=True)
class RulesConfig:
    """All rule thresholds, registries and suppressions. Versioned file-backed."""

    privileged_tools: frozenset[str] = frozenset({"shell", "file_write", "http_fetch"})
    privileged_grace_seconds: float = 30.0

    verification_failure_states: frozenset[str] = frozenset({"invalid", "unsupported_schema"})

    deny_rate_threshold: float = 0.5
    deny_rate_window_seconds: float = 3600.0
    deny_rate_min_samples: int = 5

    tool_cycle_max_calls: int = 20
    tool_cycle_window_seconds: float = 3600.0

    # release_id -> baseline privileged tools acknowledged at that release
    tool_baseline: dict[str, frozenset[str]] = field(default_factory=dict)

    unavailable_ratio_threshold: float = 0.25
    unavailable_min_events: int = 5

    patterns: dict[str, str] = field(
        default_factory=lambda: {"aws_access_key": r"AKIA[0-9A-Z]{16}"}
    )

    # tools under lease custody per ADR-0004 custody-coverage map; SEC-010
    # only evaluates tools declared covered here.
    custody_covered_tools: frozenset[str] = frozenset()

    suppressions: tuple[Suppression, ...] = ()

    version: str = "1"


# ------------------------------------------------------------------ rules ---


class Rule(Protocol):
    id: str
    version: str
    description: str

    def evaluate(self, events: Sequence[Event], config: RulesConfig, /) -> list[Finding]: ...


def _sort(events: Sequence[Event]) -> list[Event]:
    """Deterministic order: by (at, ref, kind)."""
    return sorted(events, key=lambda e: (e.at, e.ref or "", e.kind))


def _apply_suppressions(
    rule: Rule,
    findings: list[Finding],
    config: RulesConfig,
    by_ref: dict[str, Event],
) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        primary = by_ref.get(f.evidence_refs[0]) if f.evidence_refs else None
        hit = (
            next(s for s in config.suppressions if s.applies(rule.id, f.subject, primary))
            if any(s.applies(rule.id, f.subject, primary) for s in config.suppressions)
            else None
        )
        if hit is not None:
            out.append(replace(f, suppression_reason=hit.reason))
        else:
            out.append(f)
    return out


def _corroborated_receipt_traces(events: Sequence[Event]) -> set[str]:
    """trace_ids for which a gate receipt index row was correlated — every
    state in which a receipt EXISTS (matched, duplicate, ambiguous,
    late_arrival). Never consults trace-side-only records."""
    return {
        e.trace_id
        for e in events
        if e.kind == "correlation" and e.state in CORRELATED_RECEIPT_STATES and e.trace_id
    }


class _PrivilegedInvocationNoReceipt:
    """SEC-001: privileged invocation lacks a gate receipt after grace.

    Fires on correlation ``receipt_missing`` (already beyond grace per
    ADR-0002) where the tool is in the privileged registry. ``late_arrival``
    is corroborated — no finding; in-grace ``pending`` records are open and
    never evaluated (absence is a coverage gap, not a result).
    """

    id = "SEC-001"
    version = "1.0.0"
    description = "Privileged invocation lacks gate receipt after grace"

    def evaluate(self, events: Sequence[Event], config: RulesConfig) -> list[Finding]:
        findings: list[Finding] = []
        for e in _sort(events):
            if (
                e.kind == "correlation"
                and e.state == "receipt_missing"
                and e.tool is not None
                and e.tool in config.privileged_tools
            ):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_version=self.version,
                        severity="high",
                        confidence="high",
                        evidence_refs=(e.ref or e.trace_id or "",),
                        explanation=(
                            f"gate receipt missing after grace for "
                            f"privileged tool {e.tool!r} on trace "
                            f"{e.trace_id!r}"
                        ),
                        subject=e.tool or e.agent_id,
                    )
                )
        return findings


class _ReceiptVerificationFailure:
    """SEC-002: receipt verification failure (invalid / unsupported_schema)."""

    id = "SEC-002"
    version = "1.0.0"
    description = "Receipt verification failed (invalid or unsupported schema)"

    def evaluate(self, events: Sequence[Event], config: RulesConfig) -> list[Finding]:
        findings: list[Finding] = []
        for e in _sort(events):
            if e.kind == "verification" and e.state in config.verification_failure_states:
                severity = "high" if e.state == "invalid" else "medium"
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_version=self.version,
                        severity=severity,
                        confidence="high",
                        evidence_refs=(e.ref or e.receipt_hash or "",),
                        explanation=(
                            f"receipt verification state {e.state!r} (definitive failure, ADR-0001)"
                        ),
                    )
                )
        return findings


class _DenialRateThreshold:
    """SEC-003: per-application denial rate over threshold in a window."""

    id = "SEC-003"
    version = "1.0.0"
    description = "Denial rate per application exceeds config threshold"

    def evaluate(self, events: Sequence[Event], config: RulesConfig) -> list[Finding]:
        findings: list[Finding] = []
        win = config.deny_rate_window_seconds
        decisions = _sort(
            e
            for e in events
            if e.kind == "tool_audit" and e.decision in ("allow", "deny") and e.application
        )
        by_app: dict[str, list[Event]] = {}
        for e in decisions:
            by_app.setdefault(e.application or "", []).append(e)
        for app in sorted(by_app):
            evs = by_app[app]
            for i, start_ev in enumerate(evs):
                start = start_ev.at
                in_win = [e for e in evs[i:] if e.at < start + dt.timedelta(seconds=win)]
                if len(in_win) < config.deny_rate_min_samples:
                    continue
                denies = sum(1 for e in in_win if e.decision == "deny")
                rate = denies / len(in_win)
                if rate >= config.deny_rate_threshold:
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            rule_version=self.version,
                            severity="high",
                            confidence="medium",
                            evidence_refs=tuple(e.ref or "" for e in in_win),
                            explanation=(
                                f"denial rate {rate:.2f} over the last "
                                f"{len(in_win)} gated tool calls for "
                                f"application {app!r} exceeds "
                                f"{config.deny_rate_threshold:.2f}"
                            ),
                            subject=app,
                        )
                    )
                    break  # first qualifying window per application is enough
        return findings


class _ToolSideSuccessAfterDeny:
    """SEC-004: tool-side success after a correlated deny (high priority).

    Joins tool-audit records (vantage A) against correlated gate receipts
    (vantage G) by trace_id — an index-plane join only.
    """

    id = "SEC-004"
    version = "1.0.0"
    description = "Tool-side success observed after a correlated deny"

    def evaluate(self, events: Sequence[Event], _config: RulesConfig) -> list[Finding]:
        findings: list[Finding] = []
        denies = {
            e.trace_id
            for e in events
            if e.kind == "correlation"
            and e.decision == "deny"
            and e.state in CORRELATED_RECEIPT_STATES
            and e.trace_id
        }
        for e in _sort(events):
            if e.kind == "tool_audit" and e.outcome == "success" and e.trace_id in denies:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_version=self.version,
                        severity="critical",
                        confidence="high",
                        evidence_refs=(e.ref or e.trace_id or "",),
                        explanation=(
                            f"tool-side execution succeeded on trace "
                            f"{e.trace_id!r} whose correlated gate receipt "
                            f"decision is deny"
                        ),
                        subject=e.tool or e.agent_id,
                    )
                )
        return findings


class _RepeatedToolCallCycle:
    """SEC-005: repeated tool-call cycle exceeding a configured bound."""

    id = "SEC-005"
    version = "1.0.0"
    description = "Repeated tool-call cycle exceeds configured bound"

    def evaluate(self, events: Sequence[Event], config: RulesConfig) -> list[Finding]:
        findings: list[Finding] = []
        win = config.tool_cycle_window_seconds
        by_pair: dict[tuple[str, str], list[Event]] = {}
        for e in _sort(events):
            if e.kind == "tool_audit" and e.tool and e.agent_id:
                by_pair.setdefault((e.agent_id or "", e.tool or ""), []).append(e)
        for (agent, tool), evs in sorted(by_pair.items()):
            for i, start_ev in enumerate(evs):
                start = start_ev.at
                in_win = [e for e in evs[i:] if e.at < start + dt.timedelta(seconds=win)]
                if len(in_win) > config.tool_cycle_max_calls:
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            rule_version=self.version,
                            severity="medium",
                            confidence="medium",
                            evidence_refs=tuple(e.ref or "" for e in in_win),
                            explanation=(
                                f"{len(in_win)} tool-audit calls to {tool!r} "
                                f"by agent {agent!r} within "
                                f"{config.tool_cycle_window_seconds:.0f}s "
                                f"exceeds the bound "
                                f"{config.tool_cycle_max_calls}"
                            ),
                            subject=f"{agent}/{tool}",
                        )
                    )
                    break
        return findings


class _NewPrivilegedTool:
    """SEC-006: new privileged tool appears for an agent release.

    Fires when a privileged tool is observed against a release whose baseline
    registry (config) does not include it — a baseline change without
    acknowledgement. A release with NO baseline entry at all stays silent:
    absence of a baseline is an onboarding gap, not a finding (the registry
    is the config's job).
    """

    id = "SEC-006"
    version = "1.0.0"
    description = "Privileged tool observed outside the release baseline registry"

    def evaluate(self, events: Sequence[Event], config: RulesConfig) -> list[Finding]:
        findings: list[Finding] = []
        for e in _sort(events):
            if (
                e.kind == "tool_audit"
                and e.tool
                and e.release_id
                and e.tool in config.privileged_tools
                and e.release_id in config.tool_baseline
                and e.tool not in config.tool_baseline[e.release_id]
            ):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_version=self.version,
                        severity="high",
                        confidence="medium",
                        evidence_refs=(e.ref or e.tool or "",),
                        explanation=(
                            f"privileged tool {e.tool!r} observed against "
                            f"release {e.release_id!r} but absent from its "
                            f"acknowledged baseline registry (SEC-006 "
                            f"baseline change)"
                        ),
                        subject=e.release_id,
                    )
                )
        return findings


class _EvidenceBacklog:
    """SEC-007: evidence ingest or verifier backlog over threshold.

    FAIL VISIBLE (ADR-0001): index records unavailable count toward the
    backlog. Denominator is ingest+verification events present; the ratio
    must clear the config threshold with at least ``min_events`` samples.
    """

    id = "SEC-007"
    version = "1.0.0"
    description = "Evidence ingest / verifier backlog over threshold"

    def evaluate(self, events: Sequence[Event], config: RulesConfig) -> list[Finding]:
        findings: list[Finding] = []
        coverage = _sort(e for e in events if e.kind in ("verification", "ingest") and e.state)
        unavailable = [e for e in coverage if e.state == "unavailable"]
        total = len(coverage)
        if total >= config.unavailable_min_events:
            rate = len(unavailable) / total
            if rate >= config.unavailable_ratio_threshold:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_version=self.version,
                        severity="high",
                        confidence="medium",
                        evidence_refs=tuple(e.ref or "" for e in unavailable),
                        explanation=(
                            f"{len(unavailable)}/{total} ingest/verification "
                            f"records are unavailable — fail-visible "
                            f"coverage gap (ADR-0001); thresholds: ratio "
                            f"{config.unavailable_ratio_threshold:.2f}, "
                            f"min {config.unavailable_min_events}"
                        ),
                    )
                )
        return findings


class _CredentialInTelemetryIndex:
    """SEC-008: credential / forbidden content detected in telemetry index.

    Reports PRESENCE against named config patterns only — the matched
    substring itself is NEVER placed in any finding field (PRIV-01
    invariant: presence, not payload).
    """

    id = "SEC-008"
    version = "1.0.0"
    description = "Credential/secret pattern matched in telemetry index"

    def evaluate(self, events: Sequence[Event], config: RulesConfig) -> list[Finding]:
        findings: list[Finding] = []
        compiled = {name: re.compile(pat) for name, pat in sorted(config.patterns.items())}
        for e in _sort(events):
            if not e.content:
                continue
            matched = sorted(name for name, rx in compiled.items() if rx.search(e.content))
            if matched:
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_version=self.version,
                        severity="critical",
                        confidence="high",
                        evidence_refs=(e.ref or "",),
                        explanation=(
                            "credential pattern(s) "
                            + ", ".join(matched)
                            + " matched in telemetry index record; matched "
                            "content is redacted from this finding by design"
                        ),
                        subject=e.agent_id,
                    )
                )
        return findings


class _BypassSuspected:
    """SEC-009: tool-side privileged execution with no corroborating gate
    receipt (beyond grace). ADR-0004 semantics:

    - authoritative inputs are vantage A (tool-side audit) reconciled against
      vantage G (correlated receipt index rows); NEVER trace-only signals —
      a missing or extra trace record is never a bypass signal here;
    - ``evidence_gap`` (nothing observed on any side) is NOT a finding.

    Also fires (medium confidence) for privileged tool-audit events with no
    trace key at all: an unkeyed privileged execution cannot be corroborated
    by any receipt.
    """

    id = "SEC-009"
    version = "1.0.0"
    description = "Privileged tool-side execution with no gate receipt (bypass suspected)"

    def evaluate(self, events: Sequence[Event], _config: RulesConfig) -> list[Finding]:
        findings: list[Finding] = []
        corroborated = _corroborated_receipt_traces(events)
        for e in _sort(events):
            if e.kind != "tool_audit" or not e.tool or not e.privileged:
                continue
            if e.trace_id in corroborated:
                continue
            confidence = "medium" if e.trace_id is None else "high"
            findings.append(
                Finding(
                    rule_id=self.id,
                    rule_version=self.version,
                    severity="critical",
                    confidence=confidence,
                    evidence_refs=(e.ref or "",),
                    explanation=(
                        "bypass_suspected: privileged tool-side execution of "
                        f"{e.tool!r}"
                        + (
                            " with no trace key — cannot be corroborated by any gate receipt"
                            if e.trace_id is None
                            else f" on trace {e.trace_id!r} corroborated by "
                            "no gate receipt beyond grace"
                        )
                        + "; candidate gate circumvention — investigate as "
                        "discrepancy, not as intent (ADR-0004)"
                    ),
                    subject=e.tool or e.agent_id,
                )
            )
        return findings


class _CustodyViolation:
    """SEC-010: credential consumed with no matching issued lease.

    Only evaluated for tools declared in the custody coverage map (ADR-0004:
    detection strength scales with custody coverage). A lease covers a use
    when a ``lease_issued`` event for the same credential exists.
    """

    id = "SEC-010"
    version = "1.0.0"
    description = "Credential used with no matching issued lease (custody deployment)"

    def evaluate(self, events: Sequence[Event], config: RulesConfig) -> list[Finding]:
        findings: list[Finding] = []
        leased = {
            e.credential_id
            for e in events
            if e.kind == "custody" and e.action == "lease_issued" and e.credential_id
        }
        for e in _sort(events):
            if (
                e.kind == "custody"
                and e.action == "use"
                and e.credential_id
                and e.tool in config.custody_covered_tools
                and e.credential_id not in leased
            ):
                findings.append(
                    Finding(
                        rule_id=self.id,
                        rule_version=self.version,
                        severity="critical",
                        confidence="high",
                        evidence_refs=(e.ref or "",),
                        explanation=(
                            f"credential {e.credential_id!r} consumed for "
                            f"custody-covered tool {e.tool!r} with no "
                            f"matching issued lease — custody violation "
                            f"(ADR-0004 high-confidence signal)"
                        ),
                        subject=e.agent_id or e.credential_id,
                    )
                )
        return findings


class _ProducerIdentityAnomaly:
    """SEC-011: producer identity anomaly — mid-chain credential/identity
    change for the same agent (possible identity fragmentation across gate
    boundaries). Deterministic: producer_id change between consecutive chain
    steps for one agent."""

    id = "SEC-011"
    version = "1.0.0"
    description = "Producer identity changed mid-chain for the same agent"

    def evaluate(self, events: Sequence[Event], _config: RulesConfig) -> list[Finding]:
        findings: list[Finding] = []
        chains: dict[str, list[Event]] = {}
        for e in events:
            if e.kind == "identity" and e.agent_id and e.chain_seq is not None:
                chains.setdefault(e.agent_id, []).append(e)
        for agent in sorted(chains):
            seq = sorted(chains[agent], key=lambda e: (e.chain_seq or 0, e.ref or ""))
            for prev, cur in itertools.pairwise(seq):
                if prev.producer_id and cur.producer_id and prev.producer_id != cur.producer_id:
                    findings.append(
                        Finding(
                            rule_id=self.id,
                            rule_version=self.version,
                            severity="high",
                            confidence="medium",
                            evidence_refs=(prev.ref or "", cur.ref or ""),
                            explanation=(
                                f"producer identity changed mid-chain for "
                                f"agent {agent!r} at chain step "
                                f"{cur.chain_seq}: {prev.producer_id!r} -> "
                                f"{cur.producer_id!r} (SEC-011 anomaly; "
                                f"observed discrepancy, not intent)"
                            ),
                            subject=agent,
                        )
                    )
        return findings


ALL_RULES: tuple[Rule, ...] = (
    _PrivilegedInvocationNoReceipt(),
    _ReceiptVerificationFailure(),
    _DenialRateThreshold(),
    _ToolSideSuccessAfterDeny(),
    _RepeatedToolCallCycle(),
    _NewPrivilegedTool(),
    _EvidenceBacklog(),
    _CredentialInTelemetryIndex(),
    _BypassSuspected(),
    _CustodyViolation(),
    _ProducerIdentityAnomaly(),
)


def run_rules(
    events: Sequence[Event],
    config: RulesConfig | None = None,
    rules: Sequence[Rule] | None = None,
) -> list[Finding]:
    """Deterministically evaluate rules over index-plane events."""
    config = config or RulesConfig()
    used = list(rules) if rules is not None else list(ALL_RULES)
    by_ref: dict[str, Event] = {}
    for e in events:
        if e.ref:
            by_ref[e.ref] = e
    findings: list[Finding] = []
    for rule in used:
        found = rule.evaluate(events, config)
        findings.extend(_apply_suppressions(rule, found, config, by_ref))
    findings.sort(
        key=lambda f: (
            f.rule_id,
            f.severity,
            f.confidence,
            f.evidence_refs,
            f.explanation,
        )
    )
    return findings


# ------------------------------------------------------- config loading ----


def load_config(path: str | Path) -> RulesConfig:
    """Load versioned rules-config YAML (schema v1). Requires PyYAML."""
    # optional, config-loading convenience only — imported lazily
    import yaml  # noqa: PLC0415

    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError("rules config must be a mapping")
    if raw.get("version") != 1:
        raise ValueError(f"unsupported rules-config version: {raw.get('version')!r}")
    sec_raw = raw.get("rules", {}) or {}
    priv = sec_raw.get("privileged_tools", {}) or {}
    baseline_raw = sec_raw.get("tool_baseline", {}) or {}
    deny = sec_raw.get("deny_rate", {}) or {}
    cycle = sec_raw.get("tool_cycle", {}) or {}
    backlog = sec_raw.get("backlog", {}) or {}
    patterns_raw = sec_raw.get("patterns", {}) or {}
    supp_raw = sec_raw.get("suppressions", []) or []
    supp = tuple(
        Suppression(
            rule_id=s["rule_id"],
            reason=s["reason"],
            agent_id=s.get("agent_id"),
            tool=s.get("tool"),
            trace_id=s.get("trace_id"),
            subject=s.get("subject"),
            credential_id=s.get("credential_id"),
            release_id=s.get("release_id"),
            application=s.get("application"),
        )
        for s in supp_raw
    )
    return RulesConfig(
        privileged_tools=frozenset(priv.get("registry", [])),
        privileged_grace_seconds=float(priv.get("grace_seconds", 30.0)),
        verification_failure_states=frozenset(
            sec_raw.get("verification_failure_states", ["invalid", "unsupported_schema"])
        ),
        deny_rate_threshold=float(deny.get("threshold", 0.5)),
        deny_rate_window_seconds=float(deny.get("window_seconds", 3600.0)),
        deny_rate_min_samples=int(deny.get("min_samples", 5)),
        tool_cycle_max_calls=int(cycle.get("max_calls", 20)),
        tool_cycle_window_seconds=float(cycle.get("window_seconds", 3600.0)),
        tool_baseline={rel: frozenset(tools) for rel, tools in dict(baseline_raw).items()},
        unavailable_ratio_threshold=float(backlog.get("unavailable_ratio_threshold", 0.25)),
        unavailable_min_events=int(backlog.get("min_events", 5)),
        patterns=dict(patterns_raw),
        custody_covered_tools=frozenset(sec_raw.get("custody_covered_tools", [])),
        suppressions=supp,
        version=str(raw.get("version")),
    )


__all__ = [
    "ALL_RULES",
    "CONFIDENCES",
    "CORRELATED_RECEIPT_STATES",
    "EVENT_KINDS",
    "SEVERITIES",
    "Event",
    "Finding",
    "Rule",
    "RulesConfig",
    "Suppression",
    "load_config",
    "run_rules",
]
