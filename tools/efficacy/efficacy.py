# SPDX-License-Identifier: Apache-2.0
"""OV-10: controls-efficacy campaign runner v0.

Applies every mutation in tools/efficacy/mutations.py to the known-good
run-record fixture, runs each detector, and computes kill ratios with
EXPLICIT, BOUNDED counts — the only populations in play are the catalog
v0 classes applied to this v0 fixture set. No extrapolation beyond what
is executed: the summary's claims are the printed counts, nothing more.

Detectors v0 (each is a plain pure function over the record):

- ``linkage_detector``    — evidence-link control (catches removal).
- ``review_route_detector``  — review-route control (catches bypass).
- ``boundary_detector``   — boundary control (catches widening).
- ``replay_detector``     — replay control (catches duplicates).

Per-mutation outcome: ``killed`` if ANY detector flagged it; the
``killed_by`` list is honest about who caught what. Per-detector kill
ratio = caught / assignable, using ``DETECTOR_ASSIGNMENT`` (which
mutation classes each detector is responsible for in v0). A survivor is
a mutation no detector caught — the CLI exits 1 on survivors so a
weakened control fails the run.

Usage:

    python tools/efficacy/efficacy.py            # JSON summary, exit 0/1
    python tools/efficacy/efficacy.py --full     # include per-mutation verdicts
"""

from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import pathlib
import re

_TOOLS = pathlib.Path(__file__).resolve().parent


def _load_module(name: str):
    spec = importlib.util.spec_from_file_location(name, _TOOLS / f"{name}.py")
    assert spec is not None and spec.loader is not None, f"cannot load tools/efficacy/{name}.py"
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


_mutations = _load_module("mutations")

RUNNER_VERSION = "efficacy/runner/v0"
CAMPAIGN_ID = "ov10-efficacy-v0"

# Which mutation classes each detector is RESPONSIBLE for in v0. Ratios
# are computed against exactly these assignments.
DETECTOR_ASSIGNMENT = {
    "linkage_detector": {"evidence_link_removal"},
    "review_route_detector": {"review_route_bypass"},
    "boundary_detector": {"boundary_widening"},
    "replay_detector": {"replay_duplicate"},
}

_SHA256_RE = re.compile(r"^sha256:[a-z0-9]{61,64}$")


# --- detectors (pure functions; findings are plain strings) -----------


def linkage_detector(record: dict) -> list:
    findings = []
    hashes = {r.get("receipt_hash") for r in record.get("receipts", [])}
    for i, ref in enumerate(record.get("capability_refs", [])):
        if not ref.get("privileged"):
            continue
        link = ref.get("via_receipt_hash")
        if not link:
            findings.append(
                f"privileged capability ref [{i}] ({ref.get('tool')}) "
                "carries no via_receipt_hash linkage"
            )
        elif link not in hashes:
            findings.append(
                f"privileged capability ref [{i}] links receipt {link} "
                "which is absent from the record's receipts"
            )
    for event in record.get("governance_events", []):
        rh = event.get("receipt_hash")
        if rh and rh not in hashes:
            findings.append(
                f"governance event kind={event.get('kind')} references "
                f"receipt {rh} not present in the receipt list"
            )
    return findings


def review_route_detector(record: dict) -> list:
    findings = []
    for i, event in enumerate(record.get("governance_events", [])):
        if event.get("kind") != "review-approved":
            continue
        if not event.get("approved_by") or not event.get("approval_ref"):
            findings.append(
                f"governance event [{i}] claims review-approved with no "
                "approved_by / approval_ref: forged review route"
            )
        if event.get("decision") not in (None, "allow"):
            findings.append(f"governance event [{i}] review-approved carries inconsistent decision")
    return findings


def boundary_detector(record: dict) -> list:
    findings = []
    declared = record.get("boundaries", {}).get("tools")
    if declared is None:
        return ["no declared tool boundary: boundary control unsatisfiable"]
    sanctioned = list(_mutations.SANCTIONED_TOOLS)
    if sorted(declared) != sorted(sanctioned):
        extra = sorted(set(declared) - set(sanctioned))
        missing = sorted(set(sanctioned) - set(declared))
        if extra:
            findings.append(
                f"declared boundary admits tool(s) outside the sanctioned "
                f"closed set: {extra} — boundary widening"
            )
        if missing:
            findings.append(f"declared boundary dropped sanctioned tool(s): {missing}")
    # Receipts whose tool is outside the declared boundary are also widenings.
    if "send_email" in declared:
        for receipt in record.get("receipts", []):
            if receipt.get("tool") == "send_email" and receipt.get("decision") == "allow":
                findings.append(
                    "allow decision for a tool the fixture contract never sanctioned: send_email"
                )
    return findings


def replay_detector(record: dict) -> list:
    findings = []
    seen: dict = {}
    for i, receipt in enumerate(record.get("receipts", [])):
        rh = receipt.get("receipt_hash")
        if rh and rh in seen:
            findings.append(
                f"receipt hash {rh} appears at entries {seen[rh]} and {i}: "
                "duplicate in receipt list"
            )
        else:
            seen[rh] = i
    attached: dict = {}
    for i, event in enumerate(record.get("governance_events", [])):
        if event.get("kind") != "receipt-attached":
            continue
        rh = event.get("receipt_hash")
        if rh and rh in attached:
            findings.append(
                f"receipt-attached event [{i}] replays receipt {rh} "
                f"(first attached at event {attached[rh]})"
            )
        else:
            attached[rh] = i
    return findings


DETECTORS = {
    "linkage_detector": linkage_detector,
    "review_route_detector": review_route_detector,
    "boundary_detector": boundary_detector,
    "replay_detector": replay_detector,
}

DETECTOR_CONTROL = {
    "linkage_detector": _mutations.MUTATIONS["evidence_link_removal"].control,
    "review_route_detector": _mutations.MUTATIONS["review_route_bypass"].control,
    "boundary_detector": _mutations.MUTATIONS["boundary_widening"].control,
    "replay_detector": _mutations.MUTATIONS["replay_duplicate"].control,
}


# --- runner -----------------------------------------------------------


def run_candidate(mutation_id: str, base_record: dict) -> dict:
    """Apply one mutation, run every detector, return the verdict dict."""
    mutated = _mutations.MUTATIONS[mutation_id].apply(base_record)
    killed_by = {}
    for detector_id, fn in DETECTORS.items():
        findings = fn(mutated)
        if findings:
            killed_by[detector_id] = findings
    return {
        "mutation_id": mutation_id,
        "label": _mutations.MUTATIONS[mutation_id].label,
        "control": _mutations.MUTATIONS[mutation_id].control,
        "killed": bool(killed_by),
        "killed_by": killed_by,
        "survived_by": sorted(set(DETECTORS) - set(killed_by)),
    }


def run_campaign(base_record: dict | None = None) -> dict:
    """Full campaign over the v0 catalog. Deterministic; explicit counts."""
    record = _mutations.good_run_record() if base_record is None else copy.deepcopy(base_record)
    verdicts = [run_candidate(mid, record) for mid in _mutations.catalog_ids()]
    killed = [v for v in verdicts if v["killed"]]
    survived = [v for v in verdicts if not v["killed"]]

    per_detector = {}
    for detector_id, assignable in DETECTOR_ASSIGNMENT.items():
        caught = sum(1 for v in verdicts if detector_id in v["killed_by"])
        per_detector[detector_id] = {
            "assignable_classes": sorted(assignable),
            "assignable_count": len(assignable),
            "caught": caught,
            "kill_ratio": round(caught / len(assignable), 4) if assignable else 1.0,
        }

    per_class = {
        v["mutation_id"]: {
            "killed": v["killed"],
            "killed_by": sorted(v["killed_by"]),
            "class_mutations_run": 1,
        }
        for v in verdicts
    }

    summary = {
        "campaign_id": CAMPAIGN_ID,
        "runner_version": RUNNER_VERSION,
        "mutation_catalog_version": _mutations.MUTATION_CATALOG_VERSION,
        "fixture": "good_run_record (deterministic literal fixture, tools/efficacy/mutations.py)",
        "claims_scope": "ratios cover ONLY the v0 catalog classes on the v0 fixture; no other codebase or campaign is claimed",
        "total_classes_run": len(verdicts),
        "total_killed": len(killed),
        "total_survived": len(survived),
        "per_class": per_class,
        "per_detector": per_detector,
        "survivors": [v["mutation_id"] for v in survived],
        "all_controls_hold": not survived,
        "verdicts": verdicts,
    }
    return summary


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="OV-10 efficacy campaign runner")
    parser.add_argument(
        "--full", action="store_true", help="include per-mutation verdicts and findings"
    )
    args = parser.parse_args(argv)

    summary = run_campaign()
    if not args.full:
        summary.pop("verdicts")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["all_controls_hold"] else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
