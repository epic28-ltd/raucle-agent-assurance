# SPDX-License-Identifier: Apache-2.0
"""OV-10 controls-efficacy mutation catalog v0.

A synthetic campaign applies deliberately-weakened controls to an
(expectations, run set) pair and measures whether each detector *kills* the
mutation (flags it) or survives. The catalog reports per-mutation
detections with explicit counts and a kill ratio bounded by those counts --
kill_ratio is never claimed beyond the number of recorded attempts, and a
missed mutation is reported as `survived`, never rounded away.

Mutations (backlog OV-10):

- ``evidence-link-removal``: drop the receipts a case's receipt-hash
  evidence links name, so the verdict loses its anchor.
- ``boundary-widening``: swap a receipt (and capability ref) onto a tool
  outside the case boundary tools.
- ``review-route-bypass``: strip the human_review routes from a case that
  allows privileged tool calls.
- ``replay-duplicate``: replay an existing receipt hash through a second,
  fresh record.

Detectors are pure functions over (expectations, runset) returning a list
of finding strings; no findings means the mutant survived that detector.
"""

from __future__ import annotations

import argparse
import copy
import json
import pathlib
import sys

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_VERSION = "mutation_catalog/v0"

MUTATIONS = (
    "evidence-link-removal",
    "boundary-widening",
    "review-route-bypass",
    "replay-duplicate",
)

MUTATION_DETECTOR = {
    "evidence-link-removal": "evidence-integrity",
    "boundary-widening": "boundary-scope",
    "review-route-bypass": "review-route-presence",
    "replay-duplicate": "replay-duplicate",
}


# ---------------------------------------------------------------- mutations


def mutate(doc, runset, kind):
    """Return a mutated copy of (expectations doc, runset) for one kind."""
    doc = copy.deepcopy(doc)
    runset = copy.deepcopy(runset)
    cases = doc.get("cases") or []
    if not cases:
        raise ValueError("campaign needs at least one declared case")

    bindings = runset.get("case_bindings") or {}
    case_id = cases[0]["case_id"]
    record_ids = bindings.get(case_id, [case_id])
    target_ids = [
        rid for rid in record_ids for record in runset["records"] if record["record_id"] == rid
    ]

    if kind == "review-route-bypass":
        pass
    elif not target_ids:
        raise ValueError(
            f"{kind}: no bound run records for case {case_id!r}; refusing "
            "to run a mutation that would silently do nothing"
        )

    if kind == "evidence-link-removal":
        required = {
            link["ref"]
            for link in cases[0].get("evidence_links", [])
            if link.get("kind") == "receipt-hash"
        }
        for record in runset["records"]:
            if record["record_id"] in target_ids:
                record["receipts"] = [
                    r for r in record.get("receipts", []) if r["receipt_hash"] not in required
                ]
        return doc, runset

    if kind == "boundary-widening":
        outsider = "mutated-outside-boundary-tool"
        for record in runset["records"]:
            if record["record_id"] in target_ids and record.get("receipts"):
                record["receipts"][0]["tool"] = outsider
                record.setdefault("capability_refs", []).append(
                    {"tool": outsider, "privileged": False}
                )
        return doc, runset

    if kind == "review-route-bypass":
        if not cases[0].get("human_review"):
            raise ValueError("review-route-bypass needs a case that declares human_review")
        cases[0]["human_review"] = []
        return doc, runset

    if kind == "replay-duplicate":
        source = next(
            (r for r in runset["records"] if r["record_id"] in target_ids and r.get("receipts")),
            None,
        )
        if source is None:
            raise ValueError("replay-duplicate needs a record with receipts")
        replayed = dict(source["receipts"][0])
        replayed["provenance"] = "replayed-through-fresh-record"
        sibling = next((r for r in runset["records"] if r["record_id"] not in target_ids), None)
        if sibling is None:
            raise ValueError("replay-duplicate needs a non-case record target")
        sibling["receipts"].append(replayed)
        return doc, runset

    raise ValueError(f"unknown mutation kind: {kind!r}")


# ---------------------------------------------------------------- detectors


def _case_findings(case, runset):
    """Standalone per-case rule check (same rules as the OV-9 compiler).

    Kept local so this tool does not depend on a sibling branch's file.
    Returns reason strings; unknown gate decisions are never mapped into
    pass (rule 3).
    """
    reasons = []
    accepted = set(case["expected_outcome"]["gate_decisions"])
    required_evidence = {
        link["ref"] for link in case.get("evidence_links", []) if link.get("kind") == "receipt-hash"
    }
    allowed_tools = set((case.get("boundaries") or {}).get("tools") or [])

    bindings = runset.get("case_bindings") or {}
    record_ids = bindings.get(case["case_id"], [case["case_id"]])
    by_id = {record["record_id"]: record for record in runset.get("records", [])}
    records = [by_id[rid] for rid in record_ids if rid in by_id]
    if not records:
        return ["no-records-bound: no run record matches this case"]

    seen_hashes = set()
    for record in records:
        rid = record["record_id"]
        for receipt in record.get("receipts", []):
            seen_hashes.add(receipt["receipt_hash"])
            decision = receipt["decision"]
            if decision == "unknown":
                reasons.append(f"{rid}: gate decision unknown; never a pass")
            elif decision not in accepted:
                reasons.append(
                    f"{rid}: gate decision {decision!r} outside expected "
                    + "/".join(sorted(accepted))
                )
            tool = receipt.get("tool")
            if tool and allowed_tools and tool not in allowed_tools:
                reasons.append(
                    f"{rid}: receipt tool {tool!r} outside case boundary tools "
                    + ", ".join(sorted(allowed_tools))
                )
        for cap in record.get("capability_refs", []):
            tool = cap.get("tool")
            if tool and allowed_tools and tool not in allowed_tools:
                reasons.append(
                    f"{rid}: capability {tool!r} outside case boundary tools "
                    + ", ".join(sorted(allowed_tools))
                )
    if sorted(required_evidence - seen_hashes):
        reasons.append(
            "required-evidence-missing: no bound record carries receipt(s) "
            + ", ".join(sorted(required_evidence - seen_hashes))
        )
    return reasons


def detect_evidence_integrity(doc, runset):
    findings = []
    for case in doc.get("cases", []):
        for reason in _case_findings(case, runset):
            if "required-evidence-missing" in reason:
                findings.append(f"evidence-integrity/{case['case_id']}: {reason}")
    return findings


def detect_boundary_scope(doc, runset):
    findings = []
    for case in doc.get("cases", []):
        for reason in _case_findings(case, runset):
            if "outside case boundary tools" in reason:
                findings.append(f"boundary-scope/{case['case_id']}: {reason}")
    return findings


def detect_review_route_presence(doc, runset):
    findings = []
    for case in doc.get("cases", []):
        budgets = case.get("budgets") or {}
        privileged = (budgets.get("max_privileged_tool_calls") or 0) > 0
        if privileged and not (case.get("human_review") or []):
            findings.append(
                f"review-route-presence/{case['case_id']}: privileged tool "
                "use survives with no human_review route declared"
            )
    return findings


def detect_replay_duplicate(doc, runset):
    findings = []
    seen = {}
    for record in runset.get("records", []):
        for receipt in record.get("receipts", []):
            h = receipt["receipt_hash"]
            seen.setdefault(h, []).append(record["record_id"])
    for h, record_ids in seen.items():
        if len(record_ids) > 1:
            findings.append(
                "replay-duplicate: receipt "
                + h
                + " replayed across records "
                + ", ".join(sorted(set(record_ids)))
            )
    return findings


DETECTORS = {
    "evidence-integrity": detect_evidence_integrity,
    "boundary-scope": detect_boundary_scope,
    "review-route-presence": detect_review_route_presence,
    "replay-duplicate": detect_replay_duplicate,
}

# Which detector(s) a mutation is expected to trip. Kill accounting is
# bounded to exactly this expected pair: a mutation is killed when the
# named detector fires, survived otherwise.
ASSIGNMENTS = {
    "evidence-link-removal": ["evidence-integrity"],
    "boundary-widening": ["boundary-scope"],
    "review-route-bypass": ["review-route-presence"],
    "replay-duplicate": ["replay-duplicate"],
}


# ---------------------------------------------------------------- campaign


def run_campaign(doc, runset):
    """Apply every mutation; record per-detector kill counts, explicitly."""
    entries = []
    totals = {name: {"attempts": 0, "killed": 0, "survived": 0} for name in DETECTORS}
    for kind in MUTATIONS:
        mutated_doc, mutated_runset = mutate(doc, runset, kind)
        assigned = ASSIGNMENTS[kind]
        fired = {name: DETECTORS[name](mutated_doc, mutated_runset) for name in assigned}
        killed = any(fired[name] for name in assigned)
        survived_by = [name for name in assigned if not fired[name]]
        entry = {
            "mutation": kind,
            "assigned_detectors": assigned,
            "killed": killed,
            "findings": {name: fired[name] for name in assigned if fired[name]},
            "survived_detectors": survived_by,
        }
        if not killed:
            entry["uncaught"] = (
                "survived: no assigned detector flagged this mutant; the "
                "kill ratio deliberately counts this miss"
            )
        entries.append(entry)
        for name in assigned:
            totals[name]["attempts"] += 1
            totals[name]["killed" if fired[name] else "survived"] += 1
            totals[name]["kill_ratio"] = round(totals[name]["killed"] / totals[name]["attempts"], 4)
    catalog = {
        "schema_version": SCHEMA_VERSION,
        "note": (
            "Synthetic campaign with known outcomes over fixture data; "
            "kill ratios are counts over recorded attempts only and "
            "make no claim beyond them."
        ),
        "mutations": entries,
        "detector_summary": [{"detector": name, **stats} for name, stats in totals.items()],
    }
    catalog["human_summary"] = _render(catalog)
    return catalog


def _render(catalog):
    lines = ["Mutation campaign results (synthetic, known outcomes):"]
    for entry in catalog["mutations"]:
        state = "KILLED" if entry["killed"] else "SURVIVED"
        lines.append(
            f"- {entry['mutation']}: {state} by "
            + ", ".join(name for name in entry["assigned_detectors"] if entry["findings"].get(name))
            or "-"
        )
    for row in catalog["detector_summary"]:
        lines.append(
            f"- detector {row['detector']}: {row['killed']}/{row['attempts']} "
            f"killed (survived {row['survived']}; ratio "
            f"{row['kill_ratio']}, bounded to recorded attempts)"
        )
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="OV-10 mutation catalog v0: synthetic campaign over an "
        "expectations doc + run set, kill ratios per detector."
    )
    parser.add_argument("--expectations", required=True)
    parser.add_argument("--runset", required=True)
    parser.add_argument("--output")
    parser.add_argument("--print-summary", action="store_true")
    args = parser.parse_args(argv)

    try:
        doc = yaml.safe_load(pathlib.Path(args.expectations).read_text())
        raw = json.loads(pathlib.Path(args.runset).read_text())
        runset = (
            raw
            if isinstance(raw, dict)
            else {"schema_version": "agent_run_record/v1", "records": raw}
        )
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    catalog = run_campaign(doc, runset)
    payload = json.dumps(catalog, indent=2) + "\n"
    if args.output:
        pathlib.Path(args.output).write_text(payload)
    else:
        sys.stdout.write(payload)
    if args.print_summary:
        sys.stderr.write(catalog["human_summary"] + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
