# SPDX-License-Identifier: Apache-2.0
"""OV-12: Prebind Assurance indicators.

Derives per-receipt prebind lifecycle states from gate receipt data and red
findings. The state vocabulary is CAGE-1 (arXiv:2607.03510) boundary
outcomes: admitted, held, narrowed, escalated, refused, quarantined,
no-bind, plus one documented extension, unresolved.

The unresolved case is honest absence of evidence, not a hidden verdict: an
ambiguous, duplicated, or receipt-less action attempt is reported as
unresolved with an explicit anomaly, never promoted to a fabricated
consequence state. Two further states are evidence-backed by committed red
findings (round 2): narrowed from RED-004's verified matched_degraded
attenuation, no_bind from RED-019's unconfigured-tool no-bind denials. The
remaining zeros (held, escalated, quarantined) stay annotated: the repo
invariant (no fabricated verdicts, fail-visible) outranks the desire to
fill all seven counters.
"""

from __future__ import annotations

import json
from pathlib import Path

PREBIND_STATES = (
    "admitted",
    "held",
    "narrowed",
    "escalated",
    "refused",
    "quarantined",
    "no_bind",
    "unresolved",
)

# States the receipt-only derivation can actually populate today.
DERIVABLE_STATES = frozenset({"admitted", "refused", "unresolved"})

# Red rules that evidence prebind enforcement weaknesses: the gate or its
# tool layer admitted something beyond the documented contract. These
# suppress an unqualified 'admitted' reading in the indicator summary.
PREBIND_ENFORCEMENT_WEAKNESS_RULES = frozenset({"RED-011", "RED-013", "RED-017"})

# States additionally derivable from red-finding evidence (round 2, OV-16).
RED_DERIVABLE_STATES = frozenset({"narrowed", "no_bind"})

# Red rules that evidence a NARROWED (attenuated) boundary outcome: the forge
# suite's weaker class landed on matched_degraded — trust attenuated, not
# refused, not admitted at full strength (the CAGE-1 narrowed/attenuated
# consequence).
PREBIND_NARROWED_RULES = frozenset({"RED-004"})

# Red rules that evidence a NO_BIND outcome: a cross-server or unconfigured
# MCP tool name resolves to no policy binding at all, so the gate denies it
# on the grounds that nothing binds it (the CAGE-1 no-bind consequence).
PREBIND_NO_BIND_RULES = frozenset({"RED-019"})

# Red rules that evidence the boundary HELD (verified PASS findings).
PREBIND_BOUNDARY_HELD_RULES = frozenset({"RED-004", "RED-009", "RED-015", "RED-019"})

RECEIPT_SCHEMA_CURRENT = "provenance-receipt/v1"


def load_receipt_index(path: Path) -> list[dict]:
    """Read a receipt index JSONL, skipping '#' comment header lines.

    An undecodable line fails visibly with a named ValueError: an index
    line that never parsed is broken evidence, not absence of evidence,
    so it is neither skipped (which would under-count the boundary) nor
    crashed on with a traceback. Same rule as the correlation reader's
    missing-hash reject.
    """
    rows: list[dict] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"receipt index {path}: line {line_no} is not a JSON object ({exc})"
            ) from exc
        if not isinstance(row, dict):
            raise ValueError(
                f"receipt index {path}: line {line_no} is {type(row).__name__}, not an object"
            )
        rows.append(row)
    return rows


def derive_receipt_state(receipt: dict) -> tuple[str, list[str]]:
    """Return (state, anomalies) for one indexed receipt.

    Derivation is receipt-evidence only:

    - deny -> refused
    - allow on the current receipt schema -> admitted
    - any other case -> unresolved with an explicit anomaly
    """
    decision = receipt.get("decision")
    schema = receipt.get("schema_version")
    if decision == "deny":
        return "refused", []
    if decision == "allow" and schema == RECEIPT_SCHEMA_CURRENT:
        return "admitted", []
    anomalies = []
    if decision is None:
        anomalies.append("no_decision_recorded")
    if schema != RECEIPT_SCHEMA_CURRENT:
        anomalies.append(f"legacy_schema:{schema}")
    return "unresolved", anomalies


def _trace_grouping(receipts: list[dict]) -> list[str]:
    """Anomalies from duplicate hashes and ambiguous traces."""
    anomalies: list[str] = []
    by_hash: dict[str, list[str]] = {}
    by_trace: dict[str, set[str]] = {}
    for r in receipts:
        by_hash.setdefault(r["receipt_hash"], []).append(r["provenance"])
        by_trace.setdefault(r["trace_id"], set()).add(r["receipt_hash"])
    for h, provenances in sorted(by_hash.items()):
        if len(provenances) > 1:
            anomalies.append(f"duplicate_receipt:{h}")
    for t, hashes in sorted(by_trace.items()):
        if len(hashes) > 1:
            anomalies.append(f"ambiguous_trace:{t}")
    return anomalies


def derive_receipt_state_from_runs(runs: dict) -> list[dict]:
    """Derive the missing-receipt anomaly from committed run/span data.

    A privileged span with no receipt hash is an action attempt that crossed
    the privilege boundary yet carries no boundary receipt: reported as
    unresolved with annotation missing_receipt_at_gate. Spans with no
    receipt and no privilege (non-privileged or out-of-gate work) are not
    prebind events at all and are excluded rather than guessed.
    """
    out = []
    for run in runs.get("runs", []):
        for trace in run.get("traces", []):
            for span in trace.get("spans", []):
                out.extend(_missing_receipt_rows(run, trace, span))
    return out


def _missing_receipt_rows(run: dict, trace: dict, span: dict) -> list[dict]:
    """Unresolved rows for a privileged span carrying no boundary receipt."""
    if span.get("receipt_hash") or not span.get("privileged"):
        return []
    anomalies = ["missing_receipt_at_gate"]
    decision_seen = (span.get("attrs") or {}).get("oaa.decision_seen")
    if decision_seen is not None:
        anomalies.append(f"decision_seen:{decision_seen}")
    return [
        {
            "run_id": run.get("run_id"),
            "trace_id": trace.get("trace_id"),
            "span_id": span.get("span_id"),
            "state": "unresolved",
            "anomalies": anomalies,
        }
    ]


def _classify_red_findings(
    red_findings: list[dict] | None,
) -> tuple[list[str], dict[str, list[str]], list[str], list[str]]:
    """(held, by-rule enforcement weaknesses, narrowed, no_bind) from red findings."""
    held_findings: list[str] = []
    weak_findings_by_rule: dict[str, list[str]] = {}
    narrowed_findings: list[str] = []
    no_bind_findings: list[str] = []
    for finding in red_findings or []:
        rule = finding.get("rule")
        fid = finding.get("finding_id")
        if not fid:
            continue
        if rule in PREBIND_NARROWED_RULES:
            narrowed_findings.append(fid)
        elif rule in PREBIND_NO_BIND_RULES:
            no_bind_findings.append(fid)
        elif rule in PREBIND_ENFORCEMENT_WEAKNESS_RULES:
            weak_findings_by_rule.setdefault(rule, []).append(fid)
        if rule in PREBIND_BOUNDARY_HELD_RULES:
            # a PASS finding can evidence both the boundary-held label
            # and a narrowed/no_bind counter (RED-004, RED-019)
            held_findings.append(fid)
    return held_findings, weak_findings_by_rule, narrowed_findings, no_bind_findings


def prebind_indicators(
    receipts: list[dict],
    runs: dict | None = None,
    red_findings: list[dict] | None = None,
) -> dict:
    """Build the CAGE-1 prebind indicator set from gate evidence.

    Deterministic and offline. The full seven-state vocabulary is always
    present so the packet schema is stable; states the evidence cannot
    populate are reported as an explicit (zero-count) honest limitation
    rather than suppressed.
    """
    counts = dict.fromkeys(PREBIND_STATES, 0)
    anomalies: list[str] = []
    annotations: list[str] = []

    # Rows the derivation cannot read are malformed evidence, reported by
    # name: a dict row without a usable receipt_hash still counts (the
    # decision is real evidence) but is excluded from dup/trace grouping;
    # a row that is not an object at all carries no decision and is
    # excluded from counts entirely. Neither is guessed into a state.
    derivable: list[dict] = []
    keyable: list[dict] = []
    for idx, receipt in enumerate(receipts):
        if not isinstance(receipt, dict):
            anomalies.append(f"malformed_receipt_row:{idx}")
            continue
        derivable.append(receipt)
        if isinstance(receipt.get("receipt_hash"), str) and receipt["receipt_hash"]:
            keyable.append(receipt)
        else:
            anomalies.append(f"malformed_receipt_row:{idx}")
    receipts = derivable

    by_hash: dict[str, list[dict]] = {}
    for r in keyable:
        by_hash.setdefault(r["receipt_hash"], []).append(r)

    for receipt in receipts:
        state, per_receipt_anomalies = derive_receipt_state(receipt)
        counts[state] += 1
        anomalies.extend(per_receipt_anomalies)

    trace_anomalies = _trace_grouping(keyable)
    anomalies.extend(trace_anomalies)

    if runs is not None:
        missing_runs = derive_receipt_state_from_runs(runs)
        for row in missing_runs:
            counts["unresolved"] += 1
            anomalies.extend(row["anomalies"])

    (
        held_findings,
        weak_findings_by_rule,
        narrowed_findings,
        no_bind_findings,
    ) = _classify_red_findings(red_findings)

    red_evidence: dict[str, list[str]] = {}
    if narrowed_findings:
        red_evidence["narrowed"] = sorted(narrowed_findings)
    if no_bind_findings:
        red_evidence["no_bind"] = sorted(no_bind_findings)
    # Each evidence-backed finding increments its state once: a verified
    # matched_degraded forge outcome IS an attenuation (narrowed, not
    # refused, not full-strength admission); a denial for an unconfigured
    # tool name IS a no-bind outcome (nothing resolves to a binding).
    counts["narrowed"] += len(red_evidence.get("narrowed", []))
    counts["no_bind"] += len(red_evidence.get("no_bind", []))

    non_derivable = (
        set(PREBIND_STATES)
        - DERIVABLE_STATES
        - set(red_evidence)  # only skip states actually evidence-backed here
    )
    for state in sorted(non_derivable):
        annotations.append(
            f"{state}: not derivable from receipts, committed runs, or red "
            "findings today; count is honest zero, not silent absence"
        )

    if held_findings:
        annotations.append(
            "boundary-held red rules verified PASS: " + ", ".join(sorted(set(held_findings))[:5])
        )

    for state, fids in red_evidence.items():
        annotations.append(f"{state}: evidence-backed from red findings " + ", ".join(fids))

    return {
        "schema": "oaa.prebind-indicators/v1",
        "states": PREBIND_STATES,
        "counts": counts,
        "anomalies": sorted(set(anomalies)),
        "derivable_states": sorted(DERIVABLE_STATES),
        "red_derived_states": sorted(RED_DERIVABLE_STATES),
        "enforcement_weaknesses": dict(sorted(weak_findings_by_rule.items())),
        "red_evidence": red_evidence,
        "derivation_note": (
            "admitted/refused/unresolved are derived from gate receipts and "
            "committed run spans; narrowed and no_bind are evidence-backed from "
            "red findings (RED-004 matched_degraded attenuation, RED-019 "
            "unconfigured-tool no-bind denial); held, escalated and "
            "quarantined remain honest zeros pending receipt vocabulary in "
            "the gate itself"
        ),
        "annotation_count": len(annotations),
        "annotations": annotations,
    }
