# SPDX-License-Identifier: Apache-2.0
"""Action Object + AEC assembly + replay-record completeness tests."""

from __future__ import annotations

import datetime as dt
import json

import pytest

from oaa_epaec.objects import (
    EP_AEC_VERSION,
    EVALUATOR_PROFILE_DIGEST,
    NATIVE_VERIFIER_PROFILE_DIGEST,
    REPLAY_VERSION,
    SATISFIED,
    UNSATISFIED,
    ActionBuild,
    ComponentFact,
    RequirementRejected,
    assemble_aec,
    build_action,
    build_replay_record,
    evaluate_requirement,
    jcs,
    jcs_digest,
    trust_snapshot_digest,
)

FROZEN = dt.datetime(2026, 11, 4, 12, 0, 0, tzinfo=dt.UTC)


def _build(**gate_extra) -> ActionBuild:
    payload = {
        "typ": "provenance-receipt/v1",
        "operation": "guardrail_scan",
        "x_gate": {
            "agent_id": "agent:evd",
            "acting_for": "user:alice",
            "approval_id": "",
            "decision": "allow",
            "tool": "read_file",
            "trace_id": "tr-1",
            **gate_extra,
        },
    }
    return build_action({"receipt_hash": "sha256:" + "ab" * 32, "payload": payload})


class TestActionObject:
    def test_fields_from_x_gate(self):
        b = _build()
        a = b.action
        assert a["tool"] == "read_file"
        assert a["principal"] == "agent:evd"
        assert a["trace_id"] == "tr-1"
        assert a["delegated_authority"] == {"acting_for": "user:alice"}

    def test_args_digest_descriptive_placeholder(self):
        b = _build()
        assert b.action["args_digest_basis"] == "descriptive"
        assert b.args_digest_basis == "descriptive"
        # receipt-derived: distinct receipt hash → distinct placeholder digest
        other = build_action(
            {
                "receipt_hash": "sha256:" + "cd" * 32,
                "payload": {"x_gate": {"tool": "read_file", "agent_id": "agent:evd"}},
            }
        )
        assert other.action["args_digest"] != b.action["args_digest"]

    def test_args_digest_from_x_gate_args(self):
        b = _build(args={"path": "/var/oaa-demo/synthetic/x"})
        assert b.action["args_digest_basis"] == "x_gate-args"
        # digest binds the JCS of the args, deterministically
        assert b.action["args_digest"] == jcs_digest(
            {"args": {"path": "/var/oaa-demo/synthetic/x"}}
        )
        # large args dict still canonicalises via the JCS subset
        b2 = _build(args={"k" * 40: list(range(50))})
        assert b2.action["args_digest_basis"] == "x_gate-args"

    def test_action_digest_over_jcs_of_action(self):
        b = _build()
        assert b.action_digest == jcs_digest(b.action)
        assert b.action_digest.startswith("sha256:")

    def test_caid_descriptive_shape(self):
        b = _build()
        assert b.caid_basis == "descriptive"
        assert b.action_caid.startswith("caid:1:read_file:sha256:")
        digest_part = b.action_caid.rsplit(":", 1)[1]
        import base64

        base64.urlsafe_b64decode(digest_part + "=" * (-len(digest_part) % 4))  # decodes

    def test_caid_optional(self):
        b = build_action(
            {"receipt_hash": "sha256:" + "ab" * 32, "payload": {"x_gate": {}}},
            include_caid=False,
        )
        assert b.action_caid is None
        assert b.caid_basis == "omitted"

    def test_action_is_closed_under_jcs(self):
        b = _build()
        # byte-identical JCS on re-serialisation proves closure
        assert jcs(b.action) == jcs(json.loads(jcs(b.action)))


def _fact(rh: str = "sha256:" + "aa" * 32) -> ComponentFact:
    return ComponentFact(
        type="policy-permit",
        evidence_digest=rh,
        evidence={"receipt_hash": rh, "verification_status": "valid"},
        result="VERIFIED",
        trust_snapshot_digest=trust_snapshot_digest([]),
    )


class TestAecAssembly:
    def test_shape(self):
        b = _build()
        env = assemble_aec(b, [_fact()], "policy-permit")
        aec = env.aec
        assert aec["@version"] == EP_AEC_VERSION
        assert aec["action"] == b.action
        assert aec["action_digest"] == b.action_digest
        assert aec["requirement"] == "policy-permit"
        assert aec["components"][0]["evidence_digest"] == _fact().evidence_digest
        assert "jws" not in json.dumps(aec)

    def test_component_evidence_rejects_missing_receipt_hash(self):
        with pytest.raises(ValueError, match="receipt_hash"):
            ComponentFact(
                type="policy-permit",
                evidence_digest="sha256:" + "aa" * 32,
                evidence={},
                result="VERIFIED",
            ).to_dict()

    def test_bad_result_rejected(self):
        with pytest.raises(ValueError, match=r"VERIFIED\|ACCEPTED"):
            ComponentFact(
                type="t",
                evidence_digest="sha256:" + "aa" * 32,
                evidence={"receipt_hash": "x"},
                result="MAYBE",
            ).to_dict()

    def test_aec_digest_over_jcs(self):
        env = assemble_aec(_build(), [_fact()], "policy-permit")
        assert env.aec_digest == jcs_digest(env.aec)


class TestReplayRecord:
    def test_fields_complete(self):
        env = assemble_aec(_build(), [_fact()], "policy-permit")
        rec = build_replay_record(env, SATISFIED, ["EVAL_SATISFIED"], [_fact()], now=FROZEN)
        assert rec["@version"] == REPLAY_VERSION
        assert rec["aec_digest"] == env.aec_digest
        assert rec["verdict"] == SATISFIED
        assert rec["requirement"] == "policy-permit"
        assert rec["evaluated_at"] == "2026-11-04T12:00:00+00:00"
        assert rec["evaluator_profile_digest"] == EVALUATOR_PROFILE_DIGEST
        assert rec["evaluator_limits"] == {
            "max_requirement_bytes": 4096,
            "max_requirement_tokens": 256,
            "max_paren_depth": 32,
        }
        c = rec["components"][0]
        assert c["type"] == "policy-permit"
        assert c["evidence_digest"].startswith("sha256:")
        assert c["native_verifier_profile_digest"] == NATIVE_VERIFIER_PROFILE_DIGEST
        assert c["trust_snapshot_digest"].startswith("sha256:")
        assert c["result"] == "VERIFIED"
        assert "caid_mapping_verdict" in c
        assert "freshness" in c
        assert "status_checks" in c

    def test_unsatisfied_recorded_not_raised(self):
        env = assemble_aec(_build(), [_fact()], "custody-audit")
        verdict, codes = evaluate_requirement("custody-audit", ["policy-permit"])
        rec = build_replay_record(env, verdict, codes, [_fact()], now=FROZEN)
        assert rec["verdict"] == UNSATISFIED

    def test_record_digest_stable(self):
        env = assemble_aec(_build(), [_fact()], "policy-permit")
        rec = build_replay_record(env, SATISFIED, ["EVAL_SATISFIED"], [_fact()], now=FROZEN)
        from oaa_epaec.objects import replay_record_digest

        assert replay_record_digest(rec) == replay_record_digest(json.loads(jcs(rec)))

    def test_requirement_rejected_bubbles(self):
        with pytest.raises(RequirementRejected):
            evaluate_requirement("(" * 50 + "policy-permit", ["policy-permit"])
