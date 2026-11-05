# SPDX-License-Identifier: Apache-2.0
"""Independent Assurance Agent (OV-13, report review OV-20) — reference skeleton.

The IAA consumes a published evidence document (assurance packet, prebind
indicators, run records) from stdin and emits an independent review opinion
on stdout. Its structural guarantees:

1. Process isolation: it is a separate ``python -m oaa_iaa`` entry point,
   never imported by builder code. Run it against the artefact, not in the
   builder's process.
2. No builder context: the only imports are the standard library, so the
   agent cannot reach the builder's modules, fixtures, or gate state.
3. Fail-visible: malformed input exits non-zero with an explicit error on
   stderr; the opinion is never fabricated from partial input.
"""

from __future__ import annotations

import json
import sys

OPINION_SCHEMA = "oaa.independent-review-opinion/v1"
REVALIDATION_REPORT_SCHEMA = "oaa.revalidation-report/v1"

REPRODUCED = "REPRODUCED"
MISMATCH = "MISMATCH"

PASS = "pass"
CONCERN = "concern"
FAIL = "fail"


def _review_revalidation_report(evidence: dict) -> dict | None:
    """OV-20: review opinion over a packet revalidation report document.

    The agent only cites what the document carries: an honest REPRODUCED
    verdict is corroborated (with the PASS check count cited); a MISMATCH
    or an unreadable verdict is a fail-visible concern. Returns ``None``
    when the document is not a revalidation report.
    """
    if evidence.get("schema") != REVALIDATION_REPORT_SCHEMA:
        return None
    verdict = evidence.get("verdict")
    checks_raw = evidence.get("checks")
    checks = [c for c in checks_raw if isinstance(c, dict)] if isinstance(checks_raw, list) else []
    positives: list[dict] = []
    concerns: list[dict] = []

    if not isinstance(verdict, str):
        return {
            "schema": OPINION_SCHEMA,
            "evidence_schema": evidence.get("schema"),
            "verdict": FAIL,
            "positives": [],
            "concerns": [
                {
                    "code": "REVALIDATION_VERDICT_UNREADABLE",
                    "count": 1,
                    "citation": "verdict missing or not a string",
                }
            ],
        }
    if verdict == REPRODUCED:
        passed = [c["message"] for c in checks if c.get("status") == "PASS"]
        positives.append(
            {
                "code": "REVALIDATION_REPRODUCED",
                "citation": "verdict == REPRODUCED",
                "checks_cited": len(passed),
            }
        )
        failed = [c.get("message", "") for c in checks if c.get("status") == "FAIL"]
        for message in failed:
            concerns.append(
                {
                    "code": "FAILING_CHECK_UNDER_REPRODUCED_VERDICT",
                    "count": 1,
                    "citation": str(message),
                }
            )
        opinion_verdict = FAIL if failed else PASS
    elif verdict == MISMATCH:
        failed = [c for c in checks if c.get("status") == "FAIL"]
        concerns.append(
            {
                "code": "REVALIDATION_MISMATCH",
                "count": len(failed),
                "citation": "verdict == MISMATCH",
            }
        )
        opinion_verdict = FAIL
    else:
        concerns.append(
            {
                "code": "REVALIDATION_VERDICT_UNRECOGNISED",
                "count": 1,
                "citation": f"verdict == {verdict!r}",
            }
        )
        opinion_verdict = FAIL
    return {
        "schema": OPINION_SCHEMA,
        "evidence_schema": evidence.get("schema"),
        "verdict": opinion_verdict,
        "positives": positives,
        "concerns": concerns,
        "isolation_note": (
            "opinion built in an isolate process with stdlib imports only; "
            "no builder module, fixture or gate state was reachable"
        ),
    }


def review(evidence: dict) -> dict:
    """Emit a review opinion over an evidence document.

    The agent only cites what the document itself carries. Anything the
    document does not assert is recorded as a concern with a citation gap,
    never as an affirmative claim.
    """
    schema = evidence.get("schema")
    concerns: list[dict] = []
    positives: list[dict] = []

    if schema == REVALIDATION_REPORT_SCHEMA:
        return _review_revalidation_report(evidence) or {}

    indicators = evidence.get("counts") or evidence.get("indicators", {}).get("counts")
    if isinstance(indicators, dict):
        for state in ("unresolved",):
            if indicators.get(state, 0) > 0:
                concerns.append(
                    {
                        "code": "UNRESOLVED_BOUNDARY_OUTCOMES",
                        "count": indicators[state],
                        "citation": f"counts.{state} > 0",
                    }
                )
        for state in ("held", "narrowed", "escalated", "quarantined", "no_bind"):
            if indicators.get(state, 0) == 0:
                concerns.append(
                    {
                        "code": "STATE_NOT_EVIDENCED",
                        "count": 0,
                        "citation": f"counts.{state} == 0 (honest zero)",
                    }
                )
            else:
                positives.append({"code": "STATE_EVIDENCED", "citation": f"counts.{state} > 0"})
    if schema is None:
        concerns.append({"code": "NO_SCHEMA_DECLARED", "count": 1, "citation": "schema missing"})

    verdict = (
        FAIL
        if any(c["code"] == "NO_SCHEMA_DECLARED" for c in concerns)
        else (CONCERN if concerns else PASS)
    )
    return {
        "schema": OPINION_SCHEMA,
        "evidence_schema": schema,
        "verdict": verdict,
        "positives": positives,
        "concerns": concerns,
        "isolation_note": (
            "opinion built in an isolate process with stdlib imports only; "
            "no builder module, fixture or gate state was reachable"
        ),
    }


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in ("-", "review"):
        print(f"oaa_iaa: unknown argument {argv[0]!r}", file=sys.stderr)
        return 2
    raw = sys.stdin.read()
    try:
        evidence = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"oaa_iaa: evidence stdin is not valid JSON: {exc}", file=sys.stderr)
        return 1
    if not isinstance(evidence, dict):
        print("oaa_iaa: evidence must be a JSON object", file=sys.stderr)
        return 1
    print(json.dumps(review(evidence), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
