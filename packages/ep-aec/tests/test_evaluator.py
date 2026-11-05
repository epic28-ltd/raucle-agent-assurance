# SPDX-License-Identifier: Apache-2.0
"""Requirement evaluator tests: draft-fixed limits, verdict determinism,
bounded reason codes."""

from __future__ import annotations

import pytest

from oaa_epaec.objects import (
    MAX_PAREN_DEPTH,
    MAX_REQUIREMENT_BYTES,
    SATISFIED,
    UNSATISFIED,
    RequirementRejected,
    evaluate_requirement,
)

PRESENT = ["policy-permit", "custody-audit"]


class TestVerdicts:
    @pytest.mark.parametrize(
        ("req", "want"),
        [
            ("policy-permit", SATISFIED),
            ("policy-permit AND custody-audit", SATISFIED),
            ("custody-audit AND policy-permit", SATISFIED),
            ("policy-permit OR missing-atom", SATISFIED),
            ("NOT missing-atom", SATISFIED),
            ("NOT (missing-x OR policy-permit)", UNSATISFIED),
            ("(policy-permit)", SATISFIED),
            ("missing-atom", UNSATISFIED),
            ("policy-permit AND missing-atom", UNSATISFIED),
            ("missing-a AND missing-b OR policy-permit", SATISFIED),
            ("(missing-a OR missing-b) AND custody-audit", UNSATISFIED),
        ],
    )
    def test_cases(self, req, want):
        v, _ = evaluate_requirement(req, PRESENT)
        assert want == v

    def test_precedence_and_binds_tighter(self):
        # a AND missing-b OR c must read (a AND b) OR c
        v, _ = evaluate_requirement("policy-permit AND missing-b OR custody-audit", PRESENT)
        assert SATISFIED == v

    def test_reason_codes_deterministic_and_sorted(self):
        _, codes = evaluate_requirement("zzz AND aaa AND mmm", [])
        assert codes[:3] == [
            "EVAL_UNSATISFIED_ATOM:aaa",
            "EVAL_UNSATISFIED_ATOM:mmm",
            "EVAL_UNSATISFIED_ATOM:zzz",
        ]
        assert "EVAL_UNSATISFIED" == codes[-1]

    def test_satisfied_reason_code(self):
        _, codes = evaluate_requirement("policy-permit", PRESENT)
        assert ["EVAL_SATISFIED"] == codes

    def test_missing_atoms_capped(self):
        req = " AND ".join(f"m{i:03d}" for i in range(30))
        v, codes = evaluate_requirement(req, [])
        assert UNSATISFIED == v
        atom_codes = [c for c in codes if c.startswith("EVAL_UNSATISFIED_ATOM:")]
        assert len(atom_codes) == 16
        assert "EVAL_UNSATISFIED_ATOMS_TRUNCATED" in codes


class TestLimits:
    def test_byte_limit(self):
        ok = "a" * MAX_REQUIREMENT_BYTES
        evaluate_requirement(ok, [])  # at the limit: accepted by the size gate
        with pytest.raises(RequirementRejected) as e:
            evaluate_requirement(ok + "a", [])
        assert e.value.reason_code == "EVAL_LIMIT_BYTES"

    def test_token_limit(self):
        exactly = " a" + " AND a" * 127  # 255 tokens, ~1KB: inside both limits
        v, _ = evaluate_requirement(exactly, [])
        assert v in (SATISFIED, UNSATISFIED)
        with pytest.raises(RequirementRejected) as e:
            evaluate_requirement(exactly + " OR a", [])  # 257 tokens
        assert e.value.reason_code == "EVAL_LIMIT_TOKENS"

    def test_paren_nesting_limit(self):
        # depth 32 accepted, depth 33 rejected.
        ok = "(" * MAX_PAREN_DEPTH + "policy-permit" + ")" * MAX_PAREN_DEPTH
        v, _ = evaluate_requirement(ok, PRESENT)
        assert SATISFIED == v
        bad = "(" + ok
        with pytest.raises(RequirementRejected) as e:
            evaluate_requirement(bad + (""), PRESENT)  # 33 levels
        assert e.value.reason_code == "EVAL_LIMIT_NESTING"

    def test_multibyte_bytes_counted_not_chars(self):
        # 4096 * 'é' = 8192 bytes in UTF-8 but only 4096 chars.
        with pytest.raises(RequirementRejected) as e:
            evaluate_requirement("é" * MAX_REQUIREMENT_BYTES, [])
        assert e.value.reason_code == "EVAL_LIMIT_BYTES"


class TestParseErrors:
    @pytest.mark.parametrize(
        "req",
        [
            "(policy-permit",
            "policy-permit)",
            "policy-permit AND",
            "AND policy-permit",
            "policy-permit policy-permit",
            "",
            "policy-permit + audit",
        ],
    )
    def test_rejected(self, req):
        with pytest.raises(RequirementRejected) as e:
            evaluate_requirement(req, PRESENT)
        assert e.value.reason_code in ("EVAL_PARSE", "EVAL_LIMIT_BYTES")

    def test_rejection_verdict_never_satisfied(self):
        # A rejected requirement must never yield a verdict — it raises.
        with pytest.raises(RequirementRejected):
            evaluate_requirement("(" * 100 + "a" + ")" * 100, [])

    def test_rejection_is_deterministic(self):
        r1 = None
        try:
            evaluate_requirement("(" * 50 + "a", [])
        except RequirementRejected as e:
            r1 = (e.reason_code, e.detail)
        try:
            evaluate_requirement("(" * 50 + "a", [])
        except RequirementRejected as e:
            assert (e.reason_code, e.detail) == r1
