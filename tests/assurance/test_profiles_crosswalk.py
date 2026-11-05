# SPDX-License-Identifier: Apache-2.0
"""OV-4 tests: governance profiles + crosswalk applied to fixture packets.

Covers: profiles applied to fixture packets (basic pass, regulated partial),
tampered packets fail visibly, missing packet fields degrade to PARTIAL, and
UNSUPPORTED crosswalk rows stay honest (never satisfied, never claimed).
"""

from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
_SPEC = importlib.util.spec_from_file_location(
    "oaa_assurance_profiles_validator",
    REPO_ROOT / "ops" / "assurance-profiles" / "validator.py",
)
assert _SPEC is not None
validator = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(validator)  # type: ignore[union-attr]

PROFILES = validator.load_profiles()
CROSSWALK = validator.load_crosswalk()
BASIC = "basic"
REGULATED = "regulated"


def _run(packet: dict, profile: str):
    return validator.validate(packet, profile, profiles=PROFILES, crosswalk=CROSSWALK)


def _fixture_packet(**overrides) -> dict:
    """A clean, complete basic-grade packet in the documented OV-1 shape."""
    packet = {
        "schema_version": 1,
        "kind": "agent_assurance_packet",
        "agent": {"id": "demo-billing-agent", "release": "r14"},
        "capability_chain": ["shell", "file_write", "http_fetch"],
        "policy_proof_refs": ["policy://billing/http-fetch", "policy://billing/shell"],
        "receipt_chain": {"total_count": 214, "verified_count": 214, "invalid_or_missing_count": 0},
        "coverage": {
            "gate_covered_tools": ["shell", "file_write", "http_fetch"],
            "unverified_tools": [],
        },
        "governance": {
            "DORA": {
                "Art 28(1)-28(3) transaction logging": {"status": "SUPPORTED"},
                "Art 5(1) ICT risk framework": {"status": "PARTIAL"},
            },
            "EU AI Act": {
                "Art 12(1) logging": {"status": "SUPPORTED"},
                "Art 15(1) robustness and accuracy": {"status": "PARTIAL"},
            },
            "SOC 2": {"CC7.1 configuration monitoring": {"status": "SUPPORTED"}},
            "NIST AI RMF": {"MEASURE 2.5 monitoring efficacy": {"status": "SUPPORTED"}},
            "OWASP LLM Top 10": {
                "LLM01 Prompt Injection": {"status": "SUPPORTED"},
                "LLM03 Inadequate Sandboxing": {"status": "SUPPORTED"},
                "LLM08 Excessive Agency": {"status": "SUPPORTED"},
            },
        },
        "risk_annotations": ["red-run 4 Nov: 0 unexplained denies, 18 findings triaged"],
    }
    packet.update(overrides)
    return packet


# ---------------------------------------------------------------- data files


def test_crosswalk_and_profiles_are_internally_consistent() -> None:
    assert validator.self_check(profiles=PROFILES, crosswalk=CROSSWALK) == []


def test_unsupported_rows_carry_honest_reasons() -> None:
    unsupported = [r for r in CROSSWALK["rows"] if r["status"] == "UNSUPPORTED"]
    assert unsupported, "the crosswalk must not pad itself with only green rows"
    for row in unsupported:
        assert row["unsat_reason"], row["control_id"]
        assert row["evidence_field"] is None


def test_new_frameworks_present() -> None:
    frameworks = {r["framework"] for r in CROSSWALK["rows"]}
    assert {"NIST AI RMF", "OWASP LLM Top 10"} <= frameworks
    assert {"DORA", "EU AI Act", "ISO 42001", "SOC 2", "NCSC CAF"} <= frameworks


# ------------------------------------------------------------------- basic


def test_basic_profile_passes_a_clean_packet() -> None:
    result = _run(_fixture_packet(), BASIC)
    assert result["verdict"] == validator.PASS
    assert result["summary"]["fail"] == 0
    assert validator.diff(result) == []


def test_missing_packet_fields_degrade_to_partial_not_pass() -> None:
    result = _run({}, BASIC)
    assert result["verdict"] == validator.PARTIAL
    ids = {c["check_id"] for c in validator.diff(result)}
    assert "packet:shape" in ids
    assert "receipt_chain:integrity" in ids
    assert "coverage:gate" in ids


def test_invalid_receipts_fail_visibly_under_basic() -> None:
    packet = _fixture_packet(
        receipt_chain={"total_count": 214, "verified_count": 213, "invalid_or_missing_count": 1}
    )
    result = _run(packet, BASIC)
    assert result["verdict"] == validator.FAIL
    assert any(
        c["check_id"] == "receipt_chain:integrity" and c["status"] == validator.FAIL
        for c in result["checks"]
    )


def test_unverified_tools_warn_under_basic_fail_under_regulated() -> None:
    packet = _fixture_packet(
        coverage={"gate_covered_tools": ["shell"], "unverified_tools": ["http_fetch"]}
    )
    basic = _run(packet, BASIC)
    regulated = _run(packet, REGULATED)
    assert basic["verdict"] == validator.PARTIAL
    assert regulated["verdict"] == validator.FAIL


# --------------------------------------------------------------- regulated


def test_regulated_profile_is_partial_on_a_clean_packet() -> None:
    # Honest by design: crosswalk PARTIAL rows (DORA Art 5(1), EU AI Act
    # Art 15(1), ISO 42001 A.7.2) keep regulated at PARTIAL, never PASS.
    packet = _fixture_packet(
        governance={
            **_fixture_packet()["governance"],
            "ISO 42001": {"A.7.2 AI system impact assessment": {"status": "PARTIAL"}},
            "NCSC CAF": {},
        }
    )
    result = _run(packet, REGULATED)
    assert result["verdict"] == validator.PARTIAL
    diff_ids = {c["check_id"] for c in validator.diff(result)}
    assert "crosswalk:DORA:Art 5(1) ICT risk framework" in diff_ids
    assert "crosswalk:ISO 42001:A.7.2 AI system impact assessment" in diff_ids


def test_regulated_fails_on_missing_frameworks() -> None:
    result = _run(_fixture_packet(), REGULATED)
    assert result["verdict"] == validator.FAIL
    ids = {c["check_id"] for c in validator.diff(result)}
    assert "governance:framework:ISO 42001" in ids
    assert "governance:framework:NIST AI RMF" not in ids  # declared in the fixture


# ------------------------------------------------------------------ honesty


def test_unsupported_control_never_becomes_supported() -> None:
    # OWASP LLM06 Sensitive Information Disclosure is UNSUPPORTED in the
    # crosswalk: no raucle evidence field satisfies it. The validator must
    # report the honest gap, and the diff must cite the reason.
    packet = _fixture_packet(
        governance={
            **_fixture_packet()["governance"],
            "OWASP LLM Top 10": {
                **_fixture_packet()["governance"]["OWASP LLM Top 10"],
                "LLM06 Sensitive Information Disclosure": {"status": "SUPPORTED"},
            },
        }
    )
    for profile in (BASIC, REGULATED):
        result = _run(packet, profile)
        # A fabricated claim fails in EVERY profile: tampered_claim semantics.
        assert result["verdict"] == validator.FAIL
        row = next(
            c
            for c in result["checks"]
            if c["check_id"].endswith("LLM06 Sensitive Information Disclosure")
        )
        assert row["status"] == validator.FAIL
        assert "overstates" in row["note"]


def test_packet_cannot_claim_success_beyond_the_crosswalk() -> None:
    # A crosswalk PARTIAL row declared SUPPORTED in the packet is a tampered
    # claim: FAIL in every profile, with a machine-readable diff entry.
    packet = _fixture_packet(
        governance={
            **_fixture_packet()["governance"],
            "DORA": {"Art 5(1) ICT risk framework": {"status": "SUPPORTED"}},
        }
    )
    for profile in (BASIC, REGULATED):
        result = _run(packet, profile)
        assert result["verdict"] == validator.FAIL
        row = next(
            c for c in result["checks"] if c["check_id"].endswith("Art 5(1) ICT risk framework")
        )
        assert row["status"] == validator.FAIL
        assert "overstates" in row["note"]


def test_unknown_status_in_packet_is_rejected() -> None:
    packet = _fixture_packet(
        governance={
            **_fixture_packet()["governance"],
            "SOC 2": {"CC7.1 configuration monitoring": {"status": "COMPLIANT"}},
        }
    )
    result = _run(packet, BASIC)
    assert result["verdict"] == validator.FAIL
    row = next(c for c in result["checks"] if "CC7.1 configuration monitoring" in c["check_id"])
    assert "COMPLIANT" in row["actual"]


# --------------------------------------------------------------- diff shape


def test_diff_is_machine_readable() -> None:
    packet = {}
    result = _run(packet, REGULATED)
    blob = json.dumps(validator.diff(result))
    parsed = json.loads(blob)
    assert isinstance(parsed, list) and parsed
    for entry in parsed:
        assert set(entry) == {"check_id", "status", "expected", "actual", "note"}
        assert entry["status"] in ("PARTIAL", "FAIL")


def test_unknown_profile_raises() -> None:
    with pytest.raises(ValueError, match="unknown profile"):
        _run(_fixture_packet(), "unregulated")


# ---------------------------------------------------------------------- CLI


def test_cli_exit_codes_by_verdict(tmp_path: pathlib.Path) -> None:
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(_fixture_packet()))
    green = validator.main(["--packet", str(packet_path), "--profile", "basic"])
    tampered_path = tmp_path / "tampered.json"
    tampered_path.write_text(
        json.dumps(
            _fixture_packet(
                receipt_chain={
                    "total_count": 214,
                    "verified_count": 213,
                    "invalid_or_missing_count": 1,
                }
            )
        )
    )
    red = validator.main(["--packet", str(tampered_path), "--profile", "regulated"])
    assert green == 0
    assert red == 2


def test_cli_refuses_broken_profile_data(tmp_path: pathlib.Path) -> None:
    # A profile whose semantics values are not fail/warn, or whose required
    # controls are missing from the crosswalk, is rejected before packet
    # validation by self_check, so the CLI cannot gate on inconsistent data.
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(_fixture_packet()))
    broken = {
        **PROFILES,
        "profiles": {
            **PROFILES["profiles"],
            "basic": {
                **PROFILES["profiles"]["basic"],
                "required_controls": ["DORA:not a real control"],
            },
        },
    }
    problems = validator.self_check(profiles=broken, crosswalk=CROSSWALK)
    assert problems
    tmp_path.joinpath("defect").write_text(json.dumps(problems))
    assert validator.main(["--packet", str(packet_path), "--profile", "basic"]) == 0
    # shipped data is clean and gates normally
    assert validator.self_check() == []
