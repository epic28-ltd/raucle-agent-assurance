"""Behavioural baselines (BEH-01) — index-plane behavioural drift rules.

Builds per-(agent_id, release, tool) distributions over a LABELLED window
(the eval corpus is the first window: each labelled case is one run), then
evaluates advisory drift rules against a live window:

- BEH-A  volume-step change: steps per run far outside the baseline spread
  (robust >k*MAD or parametric >3 sigma, whichever the data supports first).
- BEH-B  denial-ratio shift: window denial ratio above 2x the baseline
  ratio, with a minimum call/deny count so tiny windows stay silent.
- BEH-C  late-hour volume: tool activity outside the labelled window's
  observed hour-of-day span.
- BEH-D  new tool off the acknowledged release baseline (SEC-006 reused;
  reported again as an ADVISORY behavioural finding, not re-fired as SEC-006).

Every BEH finding is ADVISORY: severity low/medium and confidence
``advisory`` — a behavioural drift is an observed discrepancy, never intent
(ADR-0004 §4), and is measured against the labelled corpus for false
positives before it ships. FP measurement is REQUIRED, not optional: the
harness in tests/eval pins the benign-case FP count and precision.

All rule outputs are deterministic: same window + same baseline -> byte
stable findings (pinned by tests).
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import json
import math
import statistics
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .core import Event, Finding, RulesConfig, _NewPrivilegedTool

CONFIDENCE_ADVISORY = "advisory"

# --- engine thresholds (module defaults; config-overridable where noted) ---
BEH_A_MAD_K_RATIO = 3.0  # steps/run > k * MAD above the baseline median
BEH_A_SIGMA = 3.0  # or > 3 sigma above the baseline mean/median spread
BEH_A_MIN_BASELINE_RUNS = 3  # fewer baseline runs for the key: stay silent
BEH_B_RATIO = 2.0  # window denial ratio > 2x baseline ratio
BEH_B_MIN_CALLS = 3  # minimum window calls for the key
BEH_B_MIN_DENIES = 1  # minimum window denies for the key
BEH_C_MIN_EVENTS = 2  # minimum late-hour events before flagging
FP_BOUND_FRACTION = 0.15  # documented benign-case FP bound (see docs)


# ------------------------------------------------------------- labelled runs


@dataclass(frozen=True)
class LabelledRun:
    """One labelled run: a run id, a ground-truth label, and its index-plane
    events. The label travels OUTSIDE the events (labels never influence a
    rule's arithmetic; they are used only for measurement and docs)."""

    run_id: str
    label: str  # "benign" | "bypass" | ... (methodology: docs/beh01-...)
    events: tuple[Event, ...]
    window_start: datetime | None = None
    window_end: datetime | None = None

    def span(self) -> tuple[datetime, datetime] | None:
        if self.window_start and self.window_end:
            return (self.window_start, self.window_end)
        stamps = [e.at for e in self.events]
        if not stamps:
            return None
        return (min(stamps), max(stamps))


# ------------------------------------------------------------ distributions


def _mad(values: Sequence[float]) -> float:
    if not values:
        return 0.0
    med = statistics.median(values)
    return statistics.median([abs(v - med) for v in values])


@dataclass(frozen=True)
class ToolDistribution:
    """Distributions for one (agent_id, release, tool) key over a window."""

    agent_id: str
    release_id: str | None
    tool: str
    runs_seen: int
    call_counts: tuple[float, ...]  # calls per run for runs that touched the tool
    steps_per_run: tuple[float, ...]  # steps per run for runs that touched the tool
    denial_ratio: float
    total_calls: int
    total_denies: int
    hour_span: tuple[int, int] | None  # observed hour-of-day [min, max]
    latency_p95_ms: float | None = None  # PLACEHOLDER: index rows carry no
    # latency; kept so the persisted schema does not change shape later.

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "release_id": self.release_id,
            "tool": self.tool,
            "runs_seen": self.runs_seen,
            "call_counts": list(self.call_counts),
            "steps_per_run": list(self.steps_per_run),
            "denial_ratio": self.denial_ratio,
            "total_calls": self.total_calls,
            "total_denies": self.total_denies,
            "hour_span": list(self.hour_span) if self.hour_span else None,
            "latency_p95_ms": self.latency_p95_ms,
        }


@dataclass(frozen=True)
class Baseline:
    """A versioned behavioural baseline over one labelled window."""

    label: str
    built_at: str
    version: str
    tools: tuple[ToolDistribution, ...]
    digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "built_at": self.built_at,
            "version": self.version,
            "digest": self.digest,
            "tools": [t.as_dict() for t in self.tools],
        }


def _key(a: ToolDistribution) -> tuple[str, str, str]:
    return (a.agent_id, a.release_id or "", a.tool)


def build_baseline(
    runs: Sequence[LabelledRun], version: str = "1", label: str | None = None
) -> Baseline:
    """Deterministically build per-(agent_id, release, tool) distributions.

    Runs are keyed per run; steps per run are the per-run sorted event
    counts (tool-audit events for the tool; all events when the run never
    touches the tool are excluded). Sorting keys and tuples makes the
    output byte-stable for the same input set.
    """
    dists: dict[tuple[str, str, str], dict[str, Any]] = {}
    for run in _sorted_runs(runs):
        hours, by_tool, release = _run_tool_split(run)
        if not by_tool:
            continue
        agent_id = run.events[0].agent_id or ""
        for tool in sorted(by_tool):
            key = (agent_id, release or "", tool)
            d = dists.setdefault(
                key,
                {
                    "call_counts": [],
                    "steps_per_run": [],
                    "calls": 0,
                    "denies": 0,
                    "hours": [],
                    "release": release,
                },
            )
            _tally_tool_events(d, by_tool[tool], hours)

    tools = _tools_from_dists(dists)
    body = {
        "label": label or (runs[0].label if runs else "unlabelled"),
        "version": version,
        "tools": [t.as_dict() for t in tools],
    }
    digest = baseline_digest(body)
    return Baseline(
        label=body["label"],
        built_at=datetime.now(UTC).isoformat(timespec="seconds"),
        version=version,
        tools=tuple(tools),
        digest=digest,
    )


def _run_tool_split(run: LabelledRun) -> tuple[list[int], dict[str, list[Event]], str | None]:
    """Per-run split: event hours, tool-audit events per tool, pinned release.

    Per-run steps are the per-run sorted event counts (tool-audit events for
    the tool; all events when the run never touches the tool are excluded).
    """
    stamps = [e.at for e in run.events]
    if not stamps:
        return [], {}, None
    hours = [s.astimezone(UTC).hour for s in stamps]
    by_tool: dict[str, list[Event]] = {}
    for e in run.events:
        if e.kind == "tool_audit" and e.tool:
            by_tool.setdefault(e.tool, []).append(e)
    releases = sorted({e.release_id or "" for e in run.events if e.kind == "tool_audit"})
    return hours, by_tool, (releases[0] if releases else None)


def _tally_tool_events(d: dict[str, Any], evs: list[Event], hours: list[int]) -> None:
    """Accumulate one run's tool events into the (agent, release, tool) bucket."""
    evs = sorted(evs, key=lambda e: (e.at, e.ref or ""))
    d["call_counts"].append(float(len(evs)))
    d["steps_per_run"].append(float(len({e.trace_id or e.ref or "" for e in evs})))
    d["calls"] += len(evs)
    d["denies"] += sum(1 for e in evs if e.decision == "deny")
    d["hours"].extend(hours)


def _tools_from_dists(dists: dict[tuple[str, str, str], dict[str, Any]]) -> list[ToolDistribution]:
    """Deterministic per-(agent_id, release, tool) distributions."""
    tools: list[ToolDistribution] = []
    for key in sorted(dists):
        d = dists[key]
        tools.append(
            ToolDistribution(
                agent_id=key[0],
                release_id=d["release"],
                tool=key[2],
                runs_seen=len(d["call_counts"]),
                call_counts=tuple(sorted(d["call_counts"])),
                steps_per_run=tuple(sorted(d["steps_per_run"])),
                denial_ratio=(d["denies"] / d["calls"]) if d["calls"] else 0.0,
                total_calls=d["calls"],
                total_denies=d["denies"],
                hour_span=(min(d["hours"]), max(d["hours"])) if d["hours"] else None,
            )
        )
    return tools


def _sorted_runs(runs: Sequence[LabelledRun]) -> list[LabelledRun]:
    return sorted(runs, key=lambda r: r.run_id)


# ------------------------------------------------------- persist + registry


def baseline_to_json(baseline: Baseline) -> str:
    return json.dumps(baseline.as_dict(), indent=2, sort_keys=True) + "\n"


def baseline_digest(d: dict[str, Any]) -> str:
    """Content digest over (label, tools) only: built_at and engine version
    never change a baseline's identity, so identical windows share a file."""
    return hashlib.sha256(
        json.dumps(
            {"label": d.get("label"), "tools": d.get("tools", [])},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:16]


def save_baseline(directory: Path, baseline: Baseline) -> Path:
    """Persist as baselines/baseline-<digest>.json + registry; determinstic
    content-addressing means re-saving an identical baseline is a no-op
    file identity."""
    directory.mkdir(parents=True, exist_ok=True)
    d = baseline.as_dict()
    digest = baseline_digest(d)
    path = directory / f"baseline-{digest}.json"
    if not path.exists():
        path.write_text(baseline_to_json(baseline), encoding="utf-8")
    registry = directory / "registry.json"
    entries: list[dict[str, Any]] = []
    if registry.exists():
        entries = json.loads(registry.read_text(encoding="utf-8"))
    entry = {
        "file": path.name,
        "digest": digest,
        "label": baseline.label,
        "version": baseline.version,
        "built_at": baseline.built_at,
        "tools": len(baseline.tools),
    }
    entries = [e for e in entries if e["file"] != path.name] + [entry]
    registry.write_text(json.dumps(entries, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def load_baseline(path: Path) -> Baseline:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    assert baseline_digest(raw) == raw.get("digest"), "baseline digest mismatch"
    tools = tuple(
        ToolDistribution(
            agent_id=t["agent_id"],
            release_id=t.get("release_id"),
            tool=t["tool"],
            runs_seen=t["runs_seen"],
            call_counts=tuple(t.get("call_counts", [])),
            steps_per_run=tuple(t.get("steps_per_run", [])),
            denial_ratio=t["denial_ratio"],
            total_calls=t["total_calls"],
            total_denies=t["total_denies"],
            hour_span=tuple(t["hour_span"]) if t.get("hour_span") else None,
            latency_p95_ms=t.get("latency_p95_ms"),
        )
        for t in raw["tools"]
    )
    return Baseline(
        label=raw["label"],
        built_at=raw["built_at"],
        version=raw["version"],
        tools=tools,
        digest=raw["digest"],
    )


# ------------------------------------------------------------ window stats


@dataclass(frozen=True)
class WindowStats:
    """Per-(agent, release, tool) statistics over the live window."""

    per_tool: dict[tuple[str, str, str], dict[str, Any]] = field(default_factory=dict)


def window_stats(runs: Sequence[LabelledRun]) -> WindowStats:
    """Compute live-window stats with the same keying as build_baseline."""
    acc: dict[tuple[str, str, str], dict[str, Any]] = {}
    for run in _sorted_runs(runs):
        events = [e for e in run.events if e.kind == "tool_audit" and e.tool]
        if not events:
            continue
        release = min({e.release_id or "" for e in events})
        by_tool: dict[str, list[Event]] = {}
        for e in events:
            by_tool.setdefault(e.tool or "", []).append(e)
        hours = [e.at.astimezone(UTC).hour for e in events]
        agent_id = run.events[0].agent_id or ""
        for tool in sorted(by_tool):
            key = (agent_id, release or "", tool)
            d = acc.setdefault(key, {"calls": 0, "denies": 0, "hours": []})
            _tally_window_events(d, by_tool[tool], hours)
    return WindowStats(per_tool=acc)


def _tally_window_events(d: dict[str, Any], evs: list[Event], hours: list[int]) -> None:
    """Accumulate live-window tool events into one (agent, release, tool)."""
    d["calls"] += len(evs)
    d["denies"] += sum(1 for e in evs if e.decision == "deny")
    d["hours"].extend(hours)


# ------------------------------------------------------------- drift rules


def _advisory(
    rule_id: str,
    version: str,
    severity: str,
    evidence_refs: tuple[str, ...],
    explanation: str,
    subject: str | None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_version=version,
        severity=severity,
        confidence=CONFIDENCE_ADVISORY,
        evidence_refs=evidence_refs,
        explanation=explanation,
        subject=subject,
    )


def _steps_exceeds(
    steps: tuple[float, ...],
    observed: float,
    mad_k: float = BEH_A_MAD_K_RATIO,
    sigma: float = BEH_A_SIGMA,
) -> tuple[bool, str]:
    """Robust (> k*MAD above median) or parametric (> 3 sigma) check.

    Degenerate spreads (all baseline runs identical) fall back to a floor of
    one step for the MAD scale: an extremely tight labelled baseline is
    itself evidence, so a single step above median + k is a drift signal
    rather than a silent rule.
    """
    med = statistics.median(steps)
    spread = _mad(steps) or 1.0
    if observed > med + mad_k * spread:
        return True, f"steps/run {observed:.1f} > median {med:.1f} + {mad_k}x MAD {spread:.1f}"
    mean = statistics.fmean(steps)
    sd = statistics.pstdev(steps)
    if sd and observed > mean + sigma * sd:
        return True, f"steps/run {observed:.1f} > mean {mean:.1f} + {sigma} sigma {sd:.1f}"
    return False, ""


class BEHAVolumeStepChange:
    """BEH-A: run volume / step-count drift versus the labelled baseline."""

    id = "BEH-A"
    version = "1.0.0"
    description = "Steps per run drifts outside the labelled baseline spread"

    def evaluate(
        self,
        baseline: Baseline,
        runs: Sequence[LabelledRun],
        min_baseline_runs: int = BEH_A_MIN_BASELINE_RUNS,
    ) -> list[Finding]:
        findings: list[Finding] = []
        stats = window_stats(runs)
        for t in baseline.tools:
            if t.runs_seen < min_baseline_runs:
                continue
            key = _key(t)
            d = stats.per_tool.get(key)
            if not d:
                continue
            observed_steps = _observed_step_max(runs, t)
            if observed_steps <= 0.0:  # integral-valued floats; no tolerance needed
                continue
            hit, why = _steps_exceeds(t.steps_per_run, observed_steps)
            if hit:
                findings.append(
                    _advisory(
                        self.id,
                        self.version,
                        "medium",
                        (f"{key[0]}/{key[2]}",),
                        f"behavioural volume drift: {why} vs labelled baseline "
                        f"({t.runs_seen} baseline runs, label {baseline.label!r}); "
                        "advisory — observed discrepancy, not intent (ADR-0004)",
                        key[0],
                    )
                )
        return sorted(findings, key=lambda f: f.evidence_refs)


def _observed_step_max(runs: Sequence[LabelledRun], t) -> float:
    """Whole run's observed tool_audit step count for the runs in window."""
    observed = 0.0
    for run in runs:
        evs = [
            e
            for e in run.events
            if e.kind == "tool_audit" and e.tool == t.tool and (e.agent_id or "") == t.agent_id
        ]
        if evs:
            observed = max(observed, float(len(evs)))
    return observed


class BEHADenialRatioShift:
    """BEH-B: window denial ratio well above the labelled baseline ratio."""

    id = "BEH-B"
    version = "1.0.0"
    description = "Denial-ratio shift above 2x the labelled baseline (min count)"

    def evaluate(
        self,
        baseline: Baseline,
        runs: Sequence[LabelledRun],
        ratio: float = BEH_B_RATIO,
        min_calls: int = BEH_B_MIN_CALLS,
        min_denies: int = BEH_B_MIN_DENIES,
    ) -> list[Finding]:
        """A window ratio above ``ratio`` x the baseline ratio is a shift; a
        zero-denial baseline shifts as soon as the window shows denials with
        enough calls (a labelled all-allow baseline is common)."""
        findings: list[Finding] = []
        stats = window_stats(runs)
        for t in baseline.tools:
            key = _key(t)
            d = stats.per_tool.get(key)
            if not d:
                continue
            if d["calls"] < min_calls or d["denies"] < min_denies:
                continue
            win_ratio = d["denies"] / d["calls"]
            if win_ratio > ratio * t.denial_ratio:
                findings.append(
                    _advisory(
                        self.id,
                        self.version,
                        "low" if t.denial_ratio else "medium",
                        (f"{key[0]}/{key[2]}",),
                        f"behavioural denial drift: window denial ratio "
                        f"{win_ratio:.2f} over {d['calls']} calls exceeds "
                        f"{ratio}x baseline ratio {t.denial_ratio:.2f}; advisory",
                        key[0],
                    )
                )
        return sorted(findings, key=lambda f: f.evidence_refs)


class BEHALateHourVolume:
    """BEH-C: tool activity outside the labelled baseline hour span."""

    id = "BEH-C"
    version = "1.0.0"
    description = "Tool activity outside the labelled baseline hour-of-day span"

    def evaluate(
        self,
        baseline: Baseline,
        runs: Sequence[LabelledRun],
        min_events: int = BEH_C_MIN_EVENTS,
    ) -> list[Finding]:
        findings: list[Finding] = []
        stats = window_stats(runs)
        for t in baseline.tools:
            if not t.hour_span:
                continue
            key = _key(t)
            d = stats.per_tool.get(key)
            if not d:
                continue
            lo, hi = t.hour_span
            late = [h for h in d["hours"] if h < lo or h > hi]
            if len(late) >= min_events:
                findings.append(
                    _advisory(
                        self.id,
                        self.version,
                        "low",
                        (f"{key[0]}/{key[2]}",),
                        f"behavioural hour drift: {len(late)} events outside the "
                        f"labelled baseline hour span {lo:02d}:00-{hi:02d}:00 UTC; "
                        "advisory — late-hour volume",
                        key[0],
                    )
                )
        return sorted(findings, key=lambda f: f.evidence_refs)


class BEHANewToolOffBaseline:
    """BEH-D: new tool off the acknowledged release baseline — SEC-006
    reused. The SEC-006 finding (already deterministic and config-driven)
    is re-reported here as an ADVISORY behavioural drift; SEC-006 itself
    still fires in the SEC pipeline, so this class never re-emits SEC-006."""

    id = "BEH-D"
    version = "1.0.0"
    description = "New privileged tool off the acknowledged release baseline (SEC-006 reused)"

    def evaluate(
        self,
        baseline: Baseline,
        runs: Sequence[LabelledRun],
        config: RulesConfig | None = None,
    ) -> list[Finding]:
        sec = _NewPrivilegedTool()
        findings: list[Finding] = []
        for run in _sorted_runs(runs):
            for f in sec.evaluate(run.events, config or RulesConfig()):
                findings.append(
                    _advisory(
                        self.id,
                        self.version,
                        "low",
                        f.evidence_refs,
                        f"behavioural new-tool drift (SEC-006 reused): {f.explanation} "
                        f"vs baseline digest {baseline.digest[:8]}; advisory",
                        f.subject,
                    )
                )
        return sorted(findings, key=lambda f: f.evidence_refs)


BEH_RULES = (
    BEHAVolumeStepChange(),
    BEHADenialRatioShift(),
    BEHALateHourVolume(),
    BEHANewToolOffBaseline(),
)


def run_beh_rules(
    baseline: Baseline,
    runs: Sequence[LabelledRun],
    config: RulesConfig | None = None,
) -> list[Finding]:
    """Deterministically evaluate all BEH-A..D advisory rules."""
    out: list[Finding] = []
    for rule in BEH_RULES:
        if isinstance(rule, BEHANewToolOffBaseline):
            out.extend(rule.evaluate(baseline, runs, config))
        else:
            out.extend(rule.evaluate(baseline, runs))
    out.sort(key=lambda f: (f.rule_id, f.evidence_refs, f.explanation))
    return out


# ------------------------------------------------------- FP measurement ----


def measure_false_positives(
    baseline: Baseline,
    runs: Sequence[LabelledRun],
    config: RulesConfig | None = None,
    benign_label: str = "benign",
    fp_bound_fraction: float = FP_BOUND_FRACTION,
) -> dict[str, Any]:
    """REQUIRED labelled FP measurement (BEH-01 acceptance).

    Runs every BEH rule over the labelled runs and reports:

    - ``cases_flagged``: runs carrying at least one BEH finding,
    - ``fp_count``: benign-labelled runs flagged (a benign case may never
      be flagged silently — see the methodology doc),
    - ``tp_count``: non-benign runs flagged,
    - ``precision``: tp / (tp + fp) when any run is flagged,
    - ``fp_bound``: documented bound ceil(fp_bound_fraction * benign_n).

    The bound is a hard assertion site for tests: benign FP above the bound
    fails the suite (see docs/beh01-labelled-corpus-methodology.md).

    The exact attribution is per-run: rules are evaluated per run against
    the SAME baseline (drift rules are per-key, so a run only carries the
    findings its own events raise).
    """
    fp_cases: list[str] = []
    tp_cases: list[str] = []
    for run in _sorted_runs(runs):
        hits = run_beh_rules(baseline, [run], config)
        if not hits:
            continue
        (tp_cases if run.label != benign_label else fp_cases).append(run.run_id)
    fp_count = len(fp_cases)
    tp_count = len(tp_cases)
    precision = (tp_count / (tp_count + fp_count)) if (tp_count + fp_count) else None
    benign_n = sum(1 for r in runs if r.label == benign_label)
    return {
        "benign_runs": benign_n,
        "non_benign_runs": len(runs) - benign_n,
        "cases_flagged": len(set(fp_cases) | set(tp_cases)),
        "fp_count": fp_count,
        "fp_cases": fp_cases,
        "tp_count": tp_count,
        "tp_cases": tp_cases,
        "precision": precision,
        "fp_bound": math.ceil(fp_bound_fraction * benign_n),
    }


__all__ = [
    "BEH_RULES",
    "BEHADenialRatioShift",
    "BEHALateHourVolume",
    "BEHANewToolOffBaseline",
    "BEHAVolumeStepChange",
    "Baseline",
    "LabelledRun",
    "ToolDistribution",
    "WindowStats",
    "baseline_to_json",
    "build_baseline",
    "load_baseline",
    "measure_false_positives",
    "run_beh_rules",
    "save_baseline",
    "window_stats",
]
