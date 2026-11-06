# SPDX-License-Identifier: Apache-2.0
"""Scenario bank harness (OV-26).

Executes a scenario-suite YAML document against committed AgentRunRecord
fixtures, offline and deterministically:

- every scenario's ``risk_category`` must resolve to a row id in
  ``schemas/scenario-taxonomy/taxonomy.json`` (the OV-11 taxonomy);
- a scenario with ``run_record`` bindings is EXECUTED only when every bound
  receipt hash exists in the committed fixture record; the observed decision
  set is compared against ``expected_gate_decisions`` and unknown decisions
  are governed by ``on_unknown`` (never silently passed - architecture rule 3);
- a scenario with no bindings, or whose bound fixture is missing, is reported
  as ``UNEXECUTED`` - the harness never infers or fabricates an outcome.

Statuses: EXECUTED_PASS, EXECUTED_FAIL, EXECUTED_ESCALATED, UNEXECUTED.
Exit 0 when every suite's scenarios are at least deterministically
classified; exit 1 for a structurally invalid suite (missing required
fields, unresolvable taxonomy id, duplicate scenario id, binding to a
fixture record that does not exist).

The results document carries no wall-clock timestamps, so two runs over the
same suite and fixtures are byte-identical.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

try:
    import yaml

    _LOAD_ERRORS: tuple[type[Exception], ...] = (yaml.YAMLError,)
except ImportError:  # pragma: no cover
    yaml = None
    _LOAD_ERRORS = (ValueError,)

SCHEMA_VERSION = "scenario_results/v1"
REPO = pathlib.Path(__file__).resolve().parents[2]
TAXONOMY_PATH = REPO / "schemas" / "scenario-taxonomy" / "taxonomy.json"
RUN_RECORDS_PATH = REPO / "services" / "investigation-ui" / "demo_data" / "agent_run_records.json"

STATUSES = ("EXECUTED_PASS", "EXECUTED_FAIL", "EXECUTED_ESCALATED", "UNEXECUTED")
ON_UNKNOWN_VALUES = ("fail", "escalate")


class SuiteError(Exception):
    """Structurally invalid suite document."""


def load_suite(path: pathlib.Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix in (".yaml", ".yml"):
        if yaml is None:  # pragma: no cover
            raise SuiteError("error: cannot load YAML suites - the PyYAML package is not installed")
        return yaml.safe_load(text)
    return json.loads(text)


def validate_suite(suite: dict, taxonomy_ids: set[str]) -> None:
    for key in ("suite_id", "context", "scenarios"):
        if key not in suite:
            raise SuiteError(f"suite: missing required field '{key}'")
    if suite["context"] not in ("banking", "insurance", "ops"):
        raise SuiteError(f"suite: unknown context '{suite['context']}'")
    scenarios = suite["scenarios"]
    if not isinstance(scenarios, list) or not scenarios:
        raise SuiteError("suite: 'scenarios' must be a non-empty list")

    seen = set()
    for sc in scenarios:
        sid = sc.get("id", "<missing>")
        if sid in seen:
            raise SuiteError(f"scenario {sid}: duplicate id")
        seen.add(sid)
        for key in (
            "id",
            "risk_category",
            "description",
            "expected_gate_decisions",
            "on_unknown",
            "evidence_requirements",
        ):
            if key not in sc:
                raise SuiteError(f"scenario {sid}: missing required field '{key}'")
        if sc["risk_category"] not in taxonomy_ids:
            raise SuiteError(
                f"scenario {sid}: risk_category '{sc['risk_category']}' does not resolve in the OV-11 taxonomy"
            )
        if sc["on_unknown"] not in ON_UNKNOWN_VALUES:
            raise SuiteError(f"scenario {sid}: on_unknown must be one of {ON_UNKNOWN_VALUES}")
        for binding in sc.get("run_record_bindings", []):
            for key in ("record_id", "receipt_hashes", "expectation_case_id"):
                if key not in binding:
                    raise SuiteError(f"scenario {sid}: binding missing required field '{key}'")
            for h in binding["receipt_hashes"]:
                if not str(h).startswith("sha256:"):
                    raise SuiteError(
                        f"scenario {sid}: receipt hash '{h}' must be a 'sha256:' reference"
                    )


def load_run_records(path: pathlib.Path = RUN_RECORDS_PATH) -> dict[str, dict]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    records = doc if isinstance(doc, list) else doc.get("records", [])
    return {r["record_id"]: r for r in records}


def run_scenario(scenario: dict, records: dict[str, dict]) -> dict:
    """Deterministically classify one scenario against committed fixtures."""
    bindings = scenario.get("run_record_bindings", [])
    if not bindings:
        return {
            "outcome": "UNEXECUTED",
            "reason": "no committed run-record fixture is bound to this scenario",
        }

    observed: list[str] = []
    missing = []
    for binding in bindings:
        record = records.get(binding["record_id"])
        if record is None:
            missing.append(binding["record_id"])
            continue
        receipt_map = {r["receipt_hash"]: r.get("decision") for r in record.get("receipts", [])}
        for h in binding["receipt_hashes"]:
            decision = receipt_map.get(h)
            if decision is None:
                missing.append(f"{binding['record_id']}:{h}")
                continue
            observed.append(decision)

    if missing:
        return {
            "outcome": "UNEXECUTED",
            "reason": "bound fixture evidence is absent from the committed run records: "
            + ", ".join(sorted(missing)),
        }

    expected = list(scenario["expected_gate_decisions"])
    on_unknown = scenario["on_unknown"]
    allowed = set(expected)
    if on_unknown == "escalate":
        allowed.add("unknown")
    disallowed = sorted({d for d in observed if d not in allowed})
    unknowns = sorted({d for d in observed if d == "unknown"})

    if disallowed:
        return {
            "outcome": "EXECUTED_FAIL",
            "observed_decisions": sorted(set(observed)),
            "disallowed": disallowed,
            "on_unknown": on_unknown,
        }
    if unknowns:
        # Unknown decisions never pass silently; they resolve to the route
        # the expectation declares (never into an allow/deny).
        return {
            "outcome": "EXECUTED_ESCALATED" if on_unknown == "escalate" else "EXECUTED_FAIL",
            "observed_decisions": sorted(set(observed)),
            "unknown_resolved_by": on_unknown,
            "on_unknown": on_unknown,
        }
    return {
        "outcome": "EXECUTED_PASS",
        "observed_decisions": sorted(set(observed)),
        "expected_gate_decisions": expected,
        "on_unknown": on_unknown,
    }


def run_suite(suite: dict, records: dict[str, dict], taxonomy_ids: set[str]) -> dict:
    validate_suite(suite, taxonomy_ids)
    results = []
    for sc in suite["scenarios"]:
        outcome = run_scenario(sc, records)
        results.append(
            {
                "scenario_id": sc["id"],
                "risk_category": sc["risk_category"],
                "outcome": outcome["outcome"],
                "detail": {k: v for k, v in outcome.items() if k != "outcome"},
                "evidence_requirements": sc["evidence_requirements"],
            }
        )
    counts = {s: sum(1 for r in results if r["outcome"] == s) for s in STATUSES}
    return {
        "schema_version": SCHEMA_VERSION,
        "suite_id": suite["suite_id"],
        "context": suite["context"],
        "scenarios_executed": len(results),
        "outcome_counts": counts,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Execute scenario suites against committed run-record fixtures (offline, deterministic)."
    )
    parser.add_argument(
        "suites", nargs="+", type=pathlib.Path, help="scenario suite YAML/JSON files"
    )
    parser.add_argument(
        "--output",
        type=pathlib.Path,
        default=None,
        help="write the scenario-results JSON document here (default: stdout)",
    )
    parser.add_argument(
        "--fail-on-executed-fail",
        action="store_true",
        help="exit 1 if any scenario classifies EXECUTED_FAIL",
    )
    args = parser.parse_args(argv)

    taxonomy = json.loads(TAXONOMY_PATH.read_text(encoding="utf-8"))
    taxonomy_ids = {row["id"] for row in taxonomy["rows"]}
    records = load_run_records()

    document = {"schema_version": SCHEMA_VERSION, "suites": []}
    try:
        for suite_path in args.suites:
            document["suites"].append(run_suite(load_suite(suite_path), records, taxonomy_ids))
    except (SuiteError, json.JSONDecodeError, OSError, *_LOAD_ERRORS) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)

    if args.fail_on_executed_fail and any(
        r["outcome"] == "EXECUTED_FAIL" for s in document["suites"] for r in s["results"]
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
