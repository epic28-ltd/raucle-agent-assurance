# SPDX-License-Identifier: Apache-2.0
"""OV-4 governance profile validator.

Validates an agent assurance packet (the versioned ``agent_assurance_packet``
shape documented in OV-1 of docs/roadmap/overnight-sprint-backlog.md) against
a governance profile (profiles.yaml: basic vs regulated) using the crosswalk
data (crosswalk.json).

Returns PASS/PARTIAL/FAIL with a machine-readable diff (every check that is
not fully satisfied). Missing packet fields degrade to PARTIAL, never to a
silent PASS: the fail-visible invariant applies to every check.

Packet fields the checks read (all optional, tolerated as PARTIAL):
``schema_version`` int, ``kind`` "agent_assurance_packet",
``receipt_chain`` {invalid_or_missing_count},
``coverage`` {unverified_tools: [...]},
``governance`` {framework: {control_id: {status: SUPPORTED|PARTIAL|...}}}
(or a flat list of {framework, control_id, status} entries).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib

import yaml

MODULE_DIR = pathlib.Path(__file__).resolve().parent

OK = "OK"
PARTIAL = "PARTIAL"
FAIL = "FAIL"
PASS = "PASS"
VERDICTS = (PASS, PARTIAL, FAIL)
CROSSWALK_STATUSES = ("SUPPORTED", "PARTIAL", "UNSUPPORTED")


def load_profiles(path: pathlib.Path | None = None) -> dict:
    return yaml.safe_load((path or MODULE_DIR / "profiles.yaml").read_text())


def load_crosswalk(path: pathlib.Path | None = None) -> dict:
    return json.loads((path or MODULE_DIR / "crosswalk.json").read_text())


def crosswalk_index(crosswalk: dict) -> dict[str, dict]:
    """Map "Framework:control_id" -> crosswalk row."""
    return {f"{row['framework']}:{row['control_id']}": row for row in crosswalk["rows"]}


def _lookup(packet: dict, dotted: str):
    """Follow a dotted path into the packet; return the value or None.

    Path segments are matched literally: a framework name with spaces such as
    "EU AI Act" or "NIST AI RMF" is one segment (paths never contain dots).
    """
    node: object = packet
    for part in dotted.split("."):
        if isinstance(node, dict) and part in node:
            node = node[part]
        else:
            return None
    return None if node is None else node


# Zero is legitimate evidence (a zero failure count); only None means missing.


def _declared_controls(governance: object) -> dict[str, str]:
    """Flatten packet.governance into {"Framework:control": declared_status}."""
    out: dict[str, str] = {}
    if isinstance(governance, dict):
        for fw, controls in governance.items():
            if isinstance(controls, dict):
                for cid, entry in controls.items():
                    status = entry.get("status") if isinstance(entry, dict) else entry
                    if isinstance(status, str):
                        out[f"{fw}:{cid}"] = status
    elif isinstance(governance, list):
        for entry in governance:
            if isinstance(entry, dict) and "framework" in entry and "control_id" in entry:
                status = entry.get("status")
                if isinstance(status, str):
                    out[f"{entry['framework']}:{entry['control_id']}"] = status
    return out


def _check(
    checks: list[dict], check_id: str, status: str, expected: str, actual: str, note: str = ""
) -> None:
    checks.append(
        {
            "check_id": check_id,
            "status": status,
            "expected": expected,
            "actual": actual,
            "note": note,
        }
    )


def _semantics(profile: dict, gap: str) -> str:
    """Map a gap type to FAIL or PARTIAL per the profile's outcome semantics."""
    raw = profile["outcome_semantics"].get(gap, "fail")
    return FAIL if raw == "fail" else PARTIAL


def _framework_declared(packet: dict, fw: str) -> bool:
    gov = packet.get("governance")
    if isinstance(gov, dict):
        return isinstance(gov.get(fw), dict)
    if isinstance(gov, list):
        return any(isinstance(e, dict) and e.get("framework") == fw for e in gov)
    return False


def validate(
    packet: dict,
    profile_name: str = "basic",
    *,
    profiles: dict | None = None,
    crosswalk: dict | None = None,
) -> dict:
    """Validate the packet against the named profile.

    Returns {profile, verdict, checks, summary}. profiles and crosswalk may be
    passed for tests; None loads the shipped data files.
    """
    profiles = profiles if profiles is not None else load_profiles()
    if profile_name not in profiles["profiles"]:
        raise ValueError(f"unknown profile: {profile_name!r}")
    profile = profiles["profiles"][profile_name]
    index = crosswalk_index(crosswalk if crosswalk is not None else load_crosswalk())
    checks: list[dict] = []

    # 1. Packet shape: the packet must identify its schema. Absent fields are
    # tolerated as PARTIAL; a packet that names the WRONG schema fails.
    kind = packet.get("kind")
    if packet.get("schema_version") and (kind is None or kind == "agent_assurance_packet"):
        _check(checks, "packet:shape", OK, "agent_assurance_packet with schema_version", "declared")
    elif kind is not None and kind != "agent_assurance_packet":
        _check(
            checks,
            "packet:shape",
            FAIL,
            "agent_assurance_packet with schema_version",
            f"kind {kind!r} unsupported and schema_version {packet.get('schema_version')!r}",
            "a packet naming the wrong schema cannot be validated",
        )
    else:
        _check(
            checks,
            "packet:shape",
            PARTIAL,
            "agent_assurance_packet with schema_version",
            "kind/schema_version missing",
            "packet fields are tolerated as PARTIAL, never silently PASS",
        )

    # 2. Receipt-chain integrity: invalid or missing receipts.
    invalid = _lookup(packet, "receipt_chain.invalid_or_missing_count")
    if invalid is None:
        _check(
            checks,
            "receipt_chain:integrity",
            PARTIAL,
            "receipt_chain evidence present in packet",
            "receipt_chain.invalid_or_missing_count missing",
            "packet fields are tolerated as PARTIAL, never silently PASS",
        )
    elif invalid == 0:
        _check(checks, "receipt_chain:integrity", OK, "invalid_or_missing_count == 0", "0")
    else:
        _check(
            checks,
            "receipt_chain:integrity",
            _semantics(profile, "invalid_receipt"),
            "invalid_or_missing_count == 0",
            f"{invalid} invalid or missing receipts",
            "receipt integrity failures are fail-visible in every profile",
        )

    # 3. Gate coverage: unverified privileged tools.
    unverified = _lookup(packet, "coverage.unverified_tools")
    if unverified is None:
        _check(
            checks,
            "coverage:gate",
            PARTIAL,
            "coverage section present in packet",
            "coverage.unverified_tools missing",
        )
    elif unverified:
        names = ", ".join(map(str, unverified))
        _check(
            checks,
            "coverage:gate",
            _semantics(profile, "unverified_tool"),
            "no unverified tools under gate custody",
            f"{len(unverified)} unverified: {names}",
        )
    else:
        _check(
            checks,
            "coverage:gate",
            OK,
            "no unverified tools under gate custody",
            "all covered tools receipted",
        )

    # 4. Required governance frameworks declared in the packet.
    for fw in profile["required_frameworks"]:
        if _framework_declared(packet, fw):
            continue
        _check(
            checks,
            f"governance:framework:{fw}",
            _semantics(profile, "missing_framework"),
            f"{fw} mapping slot declared in packet.governance",
            "absent from packet",
        )

    # 5. Required controls against the crosswalk: this is where honesty lives.
    covered: set[str] = set()
    for control_id in profile["required_controls"]:
        covered.add(control_id)
        row = index.get(control_id)
        if row is None:
            _check(
                checks,
                f"crosswalk:{control_id}",
                FAIL,
                "control id defined in crosswalk data",
                "control id not found",
                "the profile references an unknown control: broken profile, not a packet gap",
            )
            continue
        label = f"crosswalk:{control_id}"
        declared = _declared_controls(packet.get("governance")).get(control_id)
        if row["status"] == "UNSUPPORTED":
            _check(
                checks,
                label,
                _semantics(profile, "unsupported_control"),
                "control satisfied by raucle evidence",
                "UNSUPPORTED",
                row.get("unsat_reason", "no raucle evidence field satisfies this control"),
            )
            continue
        if declared is not None and declared not in CROSSWALK_STATUSES:
            _check(
                checks,
                label,
                FAIL,
                "declared status from the crosswalk vocabulary",
                f"declared {declared!r}",
                "packet declares a status the crosswalk vocabulary does not define",
            )
            continue
        if declared is None:
            _check(
                checks,
                label,
                _semantics(profile, "evidence_missing"),
                f"{control_id} declared in packet.governance",
                "control not declared in packet",
                f"crosswalk maps it to {row['evidence_field'] or 'no packet field'} ({row['status']})",
            )
            continue
        if declared == "SUPPORTED" and row["status"] != "SUPPORTED":
            _check(
                checks,
                label,
                FAIL,
                f"declared status consistent with crosswalk ({row['status']})",
                "declared SUPPORTED",
                "packet overstates coverage the crosswalk does not establish",
            )
        elif declared == row["status"] == "SUPPORTED":
            _check(
                checks,
                label,
                OK,
                "evidence for claimed control present",
                f"crosswalk SUPPORTED via {row['evidence_field']}",
            )
        else:
            _check(
                checks,
                label,
                _semantics(profile, "partial_control"),
                f"{control_id} fully evidenced",
                f"declared {declared} vs crosswalk {row['status']}",
                "the crosswalk claims only partial coverage for this control",
            )

    # 6. Declared-control consistency: EVERY control the packet declares is
    # checked against the crosswalk, including controls the profile does not
    # require. A packet cannot claim coverage the crosswalk does not establish
    # and cannot invent controls.
    for control_id, declared_status in _declared_controls(packet.get("governance")).items():
        if control_id in covered:
            continue
        label = f"declared:{control_id}"
        row = index.get(control_id)
        if row is None:
            _check(
                checks,
                label,
                FAIL,
                "declared control defined in crosswalk data",
                "not a crosswalk row",
                "packet declares a control the crosswalk does not define",
            )
        elif declared_status not in CROSSWALK_STATUSES:
            _check(
                checks,
                label,
                FAIL,
                "declared status from the crosswalk vocabulary",
                f"declared {declared_status!r}",
                "packet declares a status the crosswalk vocabulary does not define",
            )
        elif declared_status == "SUPPORTED" and row["status"] != "SUPPORTED":
            _check(
                checks,
                label,
                _semantics(profile, "tampered_claim"),
                f"declared status consistent with crosswalk ({row['status']})",
                "declared SUPPORTED",
                "packet overstates coverage the crosswalk does not establish",
            )
        else:
            _check(
                checks,
                label,
                OK,
                f"declared status consistent with crosswalk ({row['status']})",
                f"declared {declared_status}",
            )

    statuses = [c["status"] for c in checks]
    verdict = FAIL if FAIL in statuses else (PARTIAL if PARTIAL in statuses else PASS)
    return {
        "packet_sha256": _sha256_of(packet),
        "profile": profile_name,
        "verdict": verdict,
        "checks": checks,
        "summary": {
            "total": len(checks),
            "ok": statuses.count(OK),
            "partial": statuses.count(PARTIAL),
            "fail": statuses.count(FAIL),
        },
    }


def _sha256_of(packet: dict) -> str:
    canonical = json.dumps(packet, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def diff(result: dict) -> list[dict]:
    """Machine-readable diff: every check not fully satisfied."""
    return [c for c in result["checks"] if c["status"] != OK]


def self_check(*, profiles: dict | None = None, crosswalk: dict | None = None) -> list[str]:
    """Static consistency checks over the data files. Returns defects (empty = clean)."""
    profiles = profiles if profiles is not None else load_profiles()
    crosswalk = crosswalk if crosswalk is not None else load_crosswalk()
    index = crosswalk_index(crosswalk)
    problems: list[str] = []
    for name, profile in profiles["profiles"].items():
        for gap, value in profile["outcome_semantics"].items():
            if value not in ("fail", "warn"):
                problems.append(
                    f"profile {name}: semantics {gap} must be fail or warn, got {value!r}"
                )
        for control_id in profile["required_controls"]:
            if control_id not in index:
                problems.append(
                    f"profile {name}: required control {control_id!r} not present in crosswalk"
                )
    for row in crosswalk["rows"]:
        if row["status"] not in CROSSWALK_STATUSES:
            problems.append(f"crosswalk {row['control_id']}: unknown status {row['status']!r}")
        if row["status"] == "UNSUPPORTED" and not row.get("unsat_reason"):
            problems.append(
                f"crosswalk {row['control_id']}: UNSUPPORTED rows must carry an honest unsat_reason"
            )
        if row["status"] != "UNSUPPORTED" and not row.get("evidence_field"):
            problems.append(
                f"crosswalk {row['control_id']}: SUPPORTED/PARTIAL rows must cite an evidence field"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    """CLI: python ops/assurance-profiles/validator.py --packet packet.json --profile regulated"""
    parser = argparse.ArgumentParser(
        description="Validate an agent assurance packet against a governance profile."
    )
    parser.add_argument(
        "--packet", required=True, help="path to an agent_assurance_packet.json file"
    )
    parser.add_argument(
        "--profile", default="basic", help="profile name from profiles.yaml (basic or regulated)"
    )
    args = parser.parse_args(argv)

    problems = self_check()
    if problems:
        for problem in problems:
            print(f"profile-data defect: {problem}")
        return 2
    packet = json.loads(pathlib.Path(args.packet).read_text())
    result = validate(packet, args.profile)
    print(json.dumps(result, indent=2, sort_keys=True))
    return {"FAIL": 2, "PARTIAL": 1, "PASS": 0}[result["verdict"]]


if __name__ == "__main__":
    raise SystemExit(main())
