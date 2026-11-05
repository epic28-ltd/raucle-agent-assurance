# SPDX-License-Identifier: Apache-2.0
"""OV-9 release compiler: compare expectations, candidate and baseline run sets.

Inputs:

- an Agent Process Expectations document (``agent_process_expectations/v1``),
- a candidate AgentRunRecord run set (``agent_run_record/v1`` records),
- a baseline AgentRunRecord run set.

Output: a machine-readable comparison report (``release_comparison/v1``)
plus a human summary, classifying every declared control case as one of:

- ``new_failure``        baseline passed,   candidate fails
- ``persistent_failure`` baseline failed,   candidate still fails
- ``preserved_controls`` baseline passed,   candidate still passes
- ``improved``           baseline failed,   candidate now passes

Case semantics (architecture rule 3 holds here too): ``unknown`` gate
decisions are never mapped into pass -- a case whose bound records carry an
unknown decision cannot pass, governed by ``expected_outcome.on_unknown``
(``fail`` or ``escalate``; escalate is still not a pass). A case is bound to
run records by ``case_bindings`` in the run set wrapper (case_id ->
list of record_id). When omitted, the binding defaults to record ids equal
to the case id.

Per case, a run set *passes* only when every bound record holds receipts
whose decisions all fall inside ``expected_outcome.gate_decisions`` (no
unknowns), every receipt-hash evidence link of the case is present among the
bound receipts, and no receipt or capability ref touches a tool outside the
case ``boundaries.tools``. A weakened control (drop the evidence receipt,
widen the tool set, introduce unknowns) therefore reads as a failure and is
caught by classification. Tool-scope checks run only where ``boundaries.tools``
is declared: a case declaring no tool boundary imposes no tool-scope constraint.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys

import jsonschema
import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPO_ROOT / "schemas" / "agent_run_record.schema.json"

SCHEMA_VERSION = "release_comparison/v1"

CLASSIFICATIONS = (
    "new_failure",
    "persistent_failure",
    "preserved_controls",
    "improved",
)


def _load_expectations_validator():
    spec = importlib.util.spec_from_file_location(
        "oaa_expectations_validator",
        REPO_ROOT / "tools" / "expectations" / "validate.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_json(path: pathlib.Path):
    return json.loads(path.read_text())


def load_expectations(path: pathlib.Path):
    """Load + validate an expectations document (YAML or JSON)."""

    doc = yaml.safe_load(path.read_text())
    validator = _load_expectations_validator()
    problems = validator.validate_document(doc)
    if problems:
        raise ValueError(
            "expectations document failed validation:\n"
            + "\n".join(f"{ptr}: {msg}" for ptr, msg in problems)
        )
    return doc


def validate_run_set(raw):
    """Validate a run set wrapper and each record against the run schema.

    Recognised shape: {"schema_version": "agent_run_record/v1", "note": ...,
    "records": [AgentRunRecord, ...], "case_bindings": {case_id: [record_id]}}.
    A bare list of records is also accepted (no case bindings then).
    """

    if isinstance(raw, list):
        runset = {"schema_version": "agent_run_record/v1", "records": raw}
    elif isinstance(raw, dict):
        runset = raw
    else:
        raise ValueError("run set must be an object wrapper or a list of records")

    records = runset.get("records")
    if not isinstance(records, list) or not records:
        raise ValueError("run set has no records")

    schema = json.loads(SCHEMA_PATH.read_text())
    validator_cls = jsonschema.validators.validator_for(schema)
    validator = validator_cls(schema)
    for index, record in enumerate(records):
        errors = list(validator.iter_errors(record))
        if errors:
            detail = "; ".join(e.message for e in sorted(errors, key=str))
            if isinstance(record, dict):
                bad_id = record.get("record_id", "<no id>")
            else:
                # A non-object record cannot carry an id; name its type
                # instead of crashing with AttributeError.
                bad_id = f"<non-object {type(record).__name__}>"
            raise ValueError(f"records[{index}] ({bad_id}) fails agent_run_record schema: {detail}")

    bindings = runset.get("case_bindings") or {}
    if not isinstance(bindings, dict):
        raise ValueError("case_bindings must be an object of case_id -> record ids")
    known_ids = {record["record_id"] for record in records}
    for case_id, record_ids in bindings.items():
        if not isinstance(record_ids, list) or not record_ids:
            raise ValueError(f"case_bindings[{case_id!r}] must be a non-empty list")
        missing = [rid for rid in record_ids if rid not in known_ids]
        if missing:
            raise ValueError(
                f"case_bindings[{case_id!r}] references unknown record ids: " + ", ".join(missing)
            )
    return runset


def _bound_records(runset, case_id):
    bindings = runset.get("case_bindings") or {}
    record_ids = bindings.get(case_id, [case_id])
    by_id = {record["record_id"]: record for record in runset["records"]}
    return [by_id[rid] for rid in record_ids if rid in by_id]


def evaluate_case(case, runset):
    """Return {"pass": bool, "reasons": [str]} for one case against a run set."""
    reasons = []

    expected = case["expected_outcome"]
    accepted = set(expected["gate_decisions"])
    on_unknown = expected["on_unknown"]

    required_evidence = {
        link["ref"] for link in case.get("evidence_links", []) if link.get("kind") == "receipt-hash"
    }
    allowed_tools = set((case.get("boundaries") or {}).get("tools") or [])

    records = _bound_records(runset, case["case_id"])
    if not records:
        return {"pass": False, "reasons": ["no-records-bound: no run record matches this case"]}

    seen_receipt_hashes = set()
    for record in records:
        rid = record["record_id"]
        for receipt in record.get("receipts", []):
            decision = receipt["decision"]
            seen_receipt_hashes.add(receipt["receipt_hash"])
            if decision == "unknown":
                reasons.append(
                    f"{rid}: gate decision unknown (on_unknown={on_unknown}); "
                    "unknown is never mapped into pass"
                )
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

    missing_evidence = sorted(required_evidence - seen_receipt_hashes)
    if missing_evidence:
        reasons.append(
            "required-evidence-missing: no bound record carries receipt(s) "
            + ", ".join(missing_evidence)
        )

    return {"pass": not reasons, "reasons": reasons}


CLASSIFICATION_TABLE = {
    (True, True): "preserved_controls",
    (True, False): "new_failure",
    (False, False): "persistent_failure",
    (False, True): "improved",
}


def compile_comparison(expectations, baseline, candidate):
    cases = expectations["cases"]
    case_results = []
    for case in cases:
        baseline_result = evaluate_case(case, baseline)
        candidate_result = evaluate_case(case, candidate)
        classification = CLASSIFICATION_TABLE[(baseline_result["pass"], candidate_result["pass"])]
        case_results.append(
            {
                "case_id": case["case_id"],
                "classification": classification,
                "baseline": baseline_result,
                "candidate": candidate_result,
            }
        )

    counts = {name: 0 for name in CLASSIFICATIONS}
    for entry in case_results:
        counts[entry["classification"]] += 1

    report = {
        "schema_version": SCHEMA_VERSION,
        "case_set": expectations["case_set"]["name"],
        "baseline_release": _release_label(baseline),
        "candidate_release": _release_label(candidate),
        "cases": case_results,
        "summary": counts,
    }
    report["human_summary"] = render_summary(report)
    return report


def _release_label(runset):
    releases = sorted({record.get("release", "<unset>") for record in runset["records"]})
    return ", ".join(releases)


def _label(entry):
    return {
        "new_failure": "NEW FAILURE",
        "persistent_failure": "persistent failure",
        "preserved_controls": "preserved controls",
        "improved": "improved",
    }[entry["classification"]]


def render_summary(report):
    lines = [
        f"Release comparison for case set {report['case_set']!r}: "
        f"baseline {report['baseline_release']} -> candidate "
        f"{report['candidate_release']}",
    ]
    for entry in report["cases"]:
        line = (
            f"- {entry['case_id']}: {_label(entry)}"
            f" (baseline {'pass' if entry['baseline']['pass'] else 'fail'}, "
            f"candidate {'pass' if entry['candidate']['pass'] else 'fail'})"
        )
        lines.append(line)
        for reason in entry["candidate"]["reasons"]:
            lines.append(f"    candidate: {reason}")
    s = report["summary"]
    if s["new_failure"] or s["persistent_failure"]:
        verdict = (
            f"NOT SAFE TO SIGN OFF: {s['new_failure']} new failure(s), "
            f"{s['persistent_failure']} persistent failure(s); "
            f"{s['preserved_controls']} preserved, {s['improved']} improved."
        )
    else:
        verdict = (
            f"No new or persistent failures: {s['preserved_controls']} "
            f"preserved, {s['improved']} improved."
        )
    lines.append(verdict)
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="OV-9 release compiler: classify every declared control "
        "case between a baseline and a candidate run set."
    )
    parser.add_argument("--expectations", required=True)
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", help="write the comparison JSON here")
    parser.add_argument(
        "--print-summary",
        action="store_true",
        help="print the human summary to stdout",
    )
    args = parser.parse_args(argv)

    try:
        expectations = load_expectations(pathlib.Path(args.expectations))
        baseline = validate_run_set(load_json(pathlib.Path(args.baseline)))
        candidate = validate_run_set(load_json(pathlib.Path(args.candidate)))
        report = compile_comparison(expectations, baseline, candidate)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    payload = json.dumps(report, indent=2, sort_keys=False) + "\n"
    try:
        if args.output:
            pathlib.Path(args.output).write_text(payload)
        else:
            sys.stdout.write(payload)
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if args.print_summary:
        sys.stderr.write(report["human_summary"] + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
