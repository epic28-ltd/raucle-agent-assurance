# SPDX-License-Identifier: Apache-2.0
"""K2 GitHub audit normalizer tests: synthetic, field-realistic, table-driven."""

from __future__ import annotations

import hashlib

import pytest
from oaa_audit_sources.normalize import AuditSourceConfig, normalize_github


def github_event(**over: object) -> dict[str, object]:
    """Synthetic GitHub audit-log event (field-realistic; all TEST values)."""
    event: dict[str, object] = {
        "_id": "TESTIDAAAA1111",
        "@timestamp": "2026-11-04T10:00:05Z",
        "created_at": "2026-11-04T10:00:05.123+00:00",
        "action": "git.clone",
        "actor": "octocat-agent[bot]",
        "actor_is_bot": True,
        "actor_is_agent": True,
        "actor_location": {"country_code": "GB"},
        "business_category": "agent",
        "repo": "acme/agent-sandbox",
        "hashed_token": ("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        "token_scopes": "contents:read",
        "programmatic_access_type": "FINE-GRAINED-PAT",
        "integration": None,
        "application_client_id": "Iv1.EXAMPLECLIENTID",
        "request_id": "0abcEXAMPLEdef12",
        "github_verified": True,
        "user_agent": "agent-f/1.0",
    }
    event.update(over)
    return event


GITHUB_FIELDS = (
    "actor_is_bot",
    "actor_is_agent",
    "token_scopes",
    "programmatic_access_type",
    "integration",
    "application_client_id",
    "business_category",
)


def _cfg() -> AuditSourceConfig:
    return AuditSourceConfig(source="github_audit", declared_raw_fields=GITHUB_FIELDS)


def _digest_id() -> str:
    """Expected deterministic fallback id, per the documented seed formula."""
    seed = "|".join(
        (
            "octocat-agent[bot]",
            "acme/agent-sandbox",
            "git.clone",
            "2026-11-04T10:00:05Z",
            "2026-11-04T10:00:05.123+00:00",
        )
    )
    return "sha256:" + hashlib.sha256(seed.encode()).hexdigest()[:16]


_DIGEST_ROW = {
    "source_event_id": _digest_id(),
    "event_time": "2026-11-04T10:00:05Z",
    "actor": "octocat-agent[bot]",
    "session_binding": ("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    "action": "git.clone",
    "resource": "acme/agent-sandbox",
    "unverified_linkage": "github.request_id:0abcEXAMPLEdef12",
}


def test_table_github_event_mapping() -> None:
    """Table-driven: every row pins (actor, binding, action, resource)."""
    table = [
        # (event, expected)
        (
            # programmatic agent clone: token fingerprint is the binding
            github_event(),
            {
                "source_event_id": "TESTIDAAAA1111",
                "event_time": "2026-11-04T10:00:05Z",
                "actor": "octocat-agent[bot]",
                "session_binding": (
                    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
                "action": "git.clone",
                "resource": "acme/agent-sandbox",
                "unverified_linkage": "github.request_id:0abcEXAMPLEdef12",
                "raw_keys": {
                    "actor_is_bot",
                    "actor_is_agent",
                    "token_scopes",
                    "programmatic_access_type",
                    "integration",
                    "application_client_id",
                    "business_category",
                },
            },
        ),
        (
            # human actor on a branch-protection write: no binding token
            github_event(
                action="protected_branch.update_ref",
                actor="octocat",
                actor_is_bot=False,
                actor_is_agent=False,
                hashed_token=None,
                token_scopes=None,
                programmatic_access_type=None,
            ),
            {
                "source_event_id": "TESTIDAAAA1111",
                "event_time": "2026-11-04T10:00:05Z",
                "actor": "octocat",
                "session_binding": None,
                "action": "protected_branch.update_ref",
                "resource": "acme/agent-sandbox",
                "unverified_linkage": "github.request_id:0abcEXAMPLEdef12",
                None: None,  # keys checked separately below
            },
        ),
        (
            # export without the streaming row id: deterministic digest id
            github_event(_id=None),
            _DIGEST_ROW,
        ),
        (
            # created_at fallback when the export dropped @timestamp
            github_event(_id="TESTIDBBBB2222", **{"@timestamp": None}),
            {
                "source_event_id": "TESTIDBBBB2222",
                "event_time": "2026-11-04T10:00:05.123000Z",
                "actor": "octocat-agent[bot]",
                "session_binding": (
                    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
                "action": "git.clone",
                "resource": "acme/agent-sandbox",
                "unverified_linkage": "github.request_id:0abcEXAMPLEdef12",
                None: None,
            },
        ),
        (
            # repo as dict form (organisation-level audit exports)
            github_event(_id="TESTIDCCCC3333", repo={"name": "acme/x"}),
            {
                "source_event_id": "TESTIDCCCC3333",
                "event_time": "2026-11-04T10:00:05Z",
                "actor": "octocat-agent[bot]",
                "session_binding": (
                    "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
                "action": "git.clone",
                "resource": "acme/x",
                "unverified_linkage": "github.request_id:0abcEXAMPLEdef12",
                None: None,
            },
        ),
    ]
    for event, expected in table:
        (cand,) = normalize_github([event], _cfg())
        assert cand.source == "github_audit"
        assert cand.source_event_id == expected["source_event_id"]
        assert cand.event_time == expected["event_time"]
        assert cand.actor == expected["actor"]
        assert cand.session_binding == expected["session_binding"]
        assert cand.action == expected["action"]
        assert cand.resource == expected["resource"]
        # request_id is recorded as UNVERIFIABLE linkage only, never binding
        if expected.get("unverified_linkage") is not None:
            assert cand.unverified_linkage == expected["unverified_linkage"]
            assert "request_id" not in cand.raw_ref


def test_deterministic_event_id_stable() -> None:
    a = normalize_github([github_event(_id=None)])[0]
    b = normalize_github([github_event(_id=None)])[0]
    assert a.source_event_id == b.source_event_id
    assert a.source_event_id.startswith("sha256:")


def test_no_payloads_beyond_declared_fields() -> None:
    (cand,) = normalize_github([github_event()], _cfg())
    for banned in ("request_id", "actor_location", "github_verified", "user_agent"):
        assert banned not in cand.raw_ref
    assert cand.raw_ref["actor_is_bot"] is True
    assert cand.raw_ref["actor_is_agent"] is True


def test_missing_actor_rejected() -> None:
    ev = github_event(actor=None)
    with pytest.raises(ValueError, match="lacks actor/action"):
        normalize_github([ev], _cfg())


def test_missing_action_rejected() -> None:
    ev = github_event(action="")
    with pytest.raises(ValueError, match="lacks actor/action"):
        normalize_github([ev], _cfg())


def test_missing_timestamps_rejected() -> None:
    ev = github_event(**{"@timestamp": None, "created_at": ""})
    with pytest.raises(ValueError, match="timestamp"):
        normalize_github([ev], _cfg())


def test_synthetic_marker_is_explicit() -> None:
    assert normalize_github([github_event()], _cfg())[0].synthetic is False
    assert normalize_github([github_event()], _cfg(), synthetic=True)[0].synthetic is True


def test_config_source_is_validated() -> None:
    with pytest.raises(ValueError, match="github_audit"):
        normalize_github(
            [github_event()],
            AuditSourceConfig(source="aws_cloudtrail"),
        )
