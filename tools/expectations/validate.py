# SPDX-License-Identifier: Apache-2.0
"""Agent Process Expectations validator (Sprint backlog OV-7).

Validates an expectations YAML/JSON document against
``schemas/agent_process_expectations.schema.json`` and adds semantic checks
the JSON Schema cannot express precisely enough:

1. at least one evidence link per case of kind ``receipt-hash`` (evidence
   is receipts; a trace id alone cannot anchor a verifier), and every
   receipt-hash ref must start with ``sha256:``;
2. ``human_review`` routes are required whenever a case allows privileged
   tool calls (a privileged budget with no review route is refused, not
   warned);
3. unknown gate decisions must be governed by ``on_unknown`` (``fail`` or
   ``escalate``), never mapped into pass (architecture rule 3);
4. duplicate ``case_id`` values fail;
5. boundary widening fails: per-case providers/tools must be subsets of the
   case-set ``allowed_providers`` / ``allowed_tools``.

Exit 0 on valid, exit 1 with ``error:`` lines carrying precise context
(case id, JSON pointer) for every problem found. Error text is part of the
contract.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

import jsonschema

SCHEMA_PATH = (
    pathlib.Path(__file__).resolve().parents[2]
    / "schemas"
    / "agent_process_expectations.schema.json"
)

RECEI_HASH_PATTERN = "sha256:"


def _load_document(path: pathlib.Path):
    text = path.read_text()
    if path.suffix in (".yaml", ".yml"):
        if yaml is None:
            raise SystemExit(
                "error: cannot load YAML documents - the PyYAML package is "
                "not installed in this environment"
            )
        return yaml.safe_load(text)
    return json.loads(text)


def validate_document(doc, expected_case_count=None):
    """Return a sorted list of (json pointer, precise message) problems."""
    problems = []
    schema = json.loads(SCHEMA_PATH.read_text())
    validator_cls = jsonschema.validators.validator_for(schema)
    validator = validator_cls(schema)
    for validation_error in sorted(validator.iter_errors(doc), key=str):
        pointer = "/".join(str(part) for part in validation_error.absolute_path)
        problems.append((pointer or "<document>", validation_error.message))

    cases = doc.get("cases") if isinstance(doc, dict) else None
    if isinstance(cases, list):
        case_set = doc.get("case_set") or {}
        allowed_providers = set(case_set.get("allowed_providers") or [])
        allowed_tools = set(case_set.get("allowed_tools") or [])
        seen: dict = {}
        for index, case in enumerate(cases):
            if not isinstance(case, dict):
                continue
            case_id = case.get("case_id", f"<case[{index}] no case_id>")

            if case_id in seen:
                problems.append(
                    (
                        f"cases/{index}/case_id",
                        f"error: duplicate case_id {case_id!r} already used at "
                        f"cases/{seen[case_id]}",
                    )
                )
            else:
                seen[case_id] = index

            boundaries = case.get("boundaries") or {}
            for field, allowed in (
                ("providers", allowed_providers),
                ("tools", allowed_tools),
            ):
                requested = set(boundaries.get(field) or [])
                widened = sorted(requested - allowed)
                if widened:
                    problems.append(
                        (
                            f"cases/{index}/boundaries/{field}",
                            f"error: case {case_id!r} widens the {field} "
                            "boundary: " + ", ".join(widened) + " not in case_set.allowed_" + field,
                        )
                    )

            evidence = case.get("evidence_links") or []
            receipt_kinds = [
                link
                for link in evidence
                if isinstance(link, dict)
                and link.get("kind") == "receipt-hash"
                and str(link.get("ref", "")).startswith(RECEI_HASH_PATTERN)
            ]
            if not receipt_kinds:
                problems.append(
                    (
                        f"cases/{index}/evidence_links",
                        f"error: case {case_id!r} has no receipt-hash evidence "
                        "link: at least one link of kind receipt-hash "
                        "referencing sha256: receipt bytes is required",
                    )
                )

            for link_index, link in enumerate(evidence):
                if (
                    isinstance(link, dict)
                    and link.get("kind") == "receipt-hash"
                    and not str(link.get("ref", "")).startswith(RECEI_HASH_PATTERN)
                ):
                    problems.append(
                        (
                            f"cases/{index}/evidence_links/{link_index}/ref",
                            f"error: case {case_id!r} evidence ref "
                            f"{link.get('ref')!r} must start with "
                            f"{RECEI_HASH_PATTERN} for kind receipt-hash",
                        )
                    )

            budgets = case.get("budgets") or {}
            privileges = budgets.get("max_privileged_tool_calls")
            if (privileges is not None and privileges > 0) and not bool(case.get("human_review")):
                problems.append(
                    (
                        f"cases/{index}",
                        f"error: case {case_id!r} allows privileged tool calls "
                        "(max_privileged_tool_calls > 0) but defines no "
                        "human_review route: privileged autonomy without a "
                        "review route is refused",
                    )
                )

            outcome = case.get("expected_outcome") or {}
            if outcome.get("on_unknown") not in ("fail", "escalate"):
                problems.append(
                    (
                        f"cases/{index}/expected_outcome/on_unknown",
                        f"error: case {case_id!r} must govern unknown gate "
                        "decisions: on_unknown is required and must be "
                        "'fail' or 'escalate'; unknown is never mapped into "
                        "pass",
                    )
                )

    if (
        expected_case_count is not None
        and isinstance(cases, list)
        and len(cases) != expected_case_count
    ):
        problems.append(
            (
                "cases",
                f"error: document declares {len(cases)} cases but the call "
                f"expected {expected_case_count}",
            )
        )
    return sorted(problems, key=lambda pair: pair[0])


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate an Agent Process Expectations document (OV-7)."
    )
    parser.add_argument("path")
    args = parser.parse_args(argv)
    path = pathlib.Path(args.path)
    try:
        doc = _load_document(path)
    except Exception as exc:  # precise message, non-zero exit
        print(f"error: {path} is not loadable: {exc}")
        return 1
    problems = validate_document(doc)
    if problems:
        for pointer, message in problems:
            print(f"error: at /{pointer}: {message}")
        return 1
    print(f"PASS {path}: expectations document is valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
