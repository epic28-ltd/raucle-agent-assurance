# SPDX-License-Identifier: Apache-2.0
"""K2 CloudTrail normalizer tests: synthetic, field-realistic, table-driven."""

from __future__ import annotations

import datetime as dt

import pytest
from oaa_audit_sources.normalize import (
    AuditSourceConfig,
    normalize_cloudtrail,
)

# Synthetic but field-realistic: shapes mirror real CloudTrail management
# events (CloudTrail Lake export columns / a Describe* flattening of
# LookupEvents output). Values are all EXAMPLE/TEST markers; nothing here is
# evidence.
RECEIPT_HASH = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
GATE_SESSION_TOKEN = f"oaa-{RECEIPT_HASH[:12]}"


def cloudtrail_event(**over: object) -> dict[str, object]:
    event: dict[str, object] = {
        "eventVersion": "1.09",
        "userIdentity": {
            "type": "AssumedRole",
            "principalId": f"AROAYTOK5HHLPHENAMPLE:{GATE_SESSION_TOKEN}",
            "arn": (f"arn:aws:sts::111122223333:assumed-role/agent-gate/{GATE_SESSION_TOKEN}"),
            "accountId": "111122223333",
            "accessKeyId": "ASIAEXAMPLEKEYID1234",
            "sessionContext": {
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": "AROAYTOK5HHLPHENAMPLE",
                    "arn": "arn:aws:iam::111122223333:role/agent-gate",
                    "accountId": "111122223333",
                    "userName": "agent-gate",
                },
                "attributes": {
                    "mfaAuthenticated": "false",
                    "creationDate": "2026-11-04T09:59:30Z",
                },
                "sourceIdentity": "agent:raucle-e2e",
            },
        },
        "eventTime": "2026-11-04T10:00:00Z",
        "eventSource": "ec2.amazonaws.com",
        "eventName": "RunInstances",
        "awsRegion": "eu-west-2",
        "sourceIPAddress": "203.0.113.7",
        "userAgent": "aws-sdk-python/1.34.0 botocore",
        "requestParameters": {
            "instancesSet": {
                "items": [{"imageId": "ami-0123456789abcdef0", "minCount": 1, "maxCount": 1}]
            }
        },
        "responseElements": {"instancesSet": {"items": [{"instanceId": "i-0abc123456789def01"}]}},
        "resources": [{"resourceType": "AWS::EC2::Instance", "resourceName": None}],
        "requestID": "d7ffEXAMPLE-6b1a-11ef-9ac0-EXAMPLE111111",
        "eventID": "9d1f6c7a-b026-4d21-8f9e-EXAMPLE01",
        "readOnly": False,
        "eventType": "AwsApiCall",
        "managementEvent": True,
        "recipientAccountId": "111122223333",
        "eventCategory": "Management",
    }
    event.update(over)
    return event


DEFAULT_FIELDS = ("eventSource", "recipientAccountId", "awsRegion")


def test_table_event_mapping() -> None:
    """Table: expected (actor, binding, action, resource) per event shape."""
    secrets_event = cloudtrail_event(
        eventSource="secretsmanager.amazonaws.com",
        eventName="GetSecretValue",
        readOnly=True,
        resources=[{"resourceType": "AWS::SecretsManager::Secret", "resourceName": "oaa/e2e"}],
    )
    iam_event = cloudtrail_event(
        eventName="CreateUser",
        eventSource="iam.amazonaws.com",
        userIdentity={
            "type": "IAMUser",
            "principalId": "AIDAJEXAMPLE",
            "arn": "arn:aws:iam::111122223333:user/ci-runner",
            "accountId": "111122223333",
            "userName": "ci-runner",
        },
    )
    custom_event = cloudtrail_event(
        eventSource="internaltools.example.com",
        eventName="CustomThing",
        op_map_note="unmapped event name",
    )
    table = [
        # (event, declared fields, op_map, expected fields)
        (
            cloudtrail_event(),
            DEFAULT_FIELDS,
            None,
            {
                "actor": "agent:raucle-e2e",
                "session_binding": GATE_SESSION_TOKEN,
                "action": "ec2.run_instances",
                "resource": None,  # resourceName None -> no usable resource
            },
        ),
        (
            secrets_event,
            tuple(DEFAULT_FIELDS),
            None,
            {
                "actor": "agent:raucle-e2e",
                "session_binding": GATE_SESSION_TOKEN,
                "action": "secretsmanager.get_secret_value",
                "resource": "AWS::SecretsManager::Secret/oaa/e2e",
            },
        ),
        (
            iam_event,
            DEFAULT_FIELDS,
            None,
            {
                "actor": "ci-runner",
                "session_binding": None,  # IAMUser: no session to bind
                "action": "iam.create_user",
                "resource": None,
            },
        ),
        (
            custom_event,
            DEFAULT_FIELDS,
            {"CustomThing": "internaltools.custom_thing"},
            {
                "actor": "agent:raucle-e2e",
                "session_binding": GATE_SESSION_TOKEN,
                "action": "internaltools.custom_thing",
                "resource": None,
            },
        ),
    ]
    for event, declared, op_map, expected in table:
        cfg = AuditSourceConfig(
            source="aws_cloudtrail", declared_raw_fields=declared, op_map=op_map
        )
        (cand,) = normalize_cloudtrail([event], cfg)
        assert cand.source == "aws_cloudtrail"
        assert cand.source_event_id == event["eventID"]
        assert cand.event_time == "2026-11-04T10:00:00Z"
        assert cand.actor == expected["actor"]
        assert cand.session_binding == expected["session_binding"]
        assert cand.action == expected["action"]
        assert cand.resource == expected["resource"]
        # parsed event_time is genuinely UTC
        dt.datetime.fromisoformat(cand.event_time.replace("Z", "+00:00"))


def test_utc_normalisation_offset_input() -> None:
    """eventTime with a non-UTC offset is still emitted UTC ISO with Z."""
    (cand,) = normalize_cloudtrail(
        [cloudtrail_event(eventTime="2026-11-04T13:30:00+03:30")],
        AuditSourceConfig(source="aws_cloudtrail"),
    )
    assert cand.event_time == "2026-11-04T10:00:00Z"


def test_no_payloads_beyond_declared_fields() -> None:
    """raw_ref keys are exactly the declared subset present; payloads never pass."""
    cfg = AuditSourceConfig(
        source="aws_cloudtrail",
        declared_raw_fields=("awsRegion", "recipientAccountId", "resources"),
    )
    (cand,) = normalize_cloudtrail([cloudtrail_event()], cfg)
    assert set(cand.raw_ref) == {"awsRegion", "recipientAccountId", "resources"}
    assert cand.raw_ref["awsRegion"] == "eu-west-2"
    for banned in ("requestParameters", "responseElements", "userAgent", "requestID"):
        assert banned not in cand.raw_ref


def test_default_config_declares_no_payload_fields() -> None:
    (cand,) = normalize_cloudtrail([cloudtrail_event()])
    assert set(cand.raw_ref) == {"eventSource", "recipientAccountId", "awsRegion"}


def test_event_without_event_id_is_rejected() -> None:
    with pytest.raises(ValueError, match="eventID"):
        normalize_cloudtrail([cloudtrail_event(eventID=None)])


def test_event_without_timestamp_is_rejected() -> None:
    with pytest.raises(ValueError, match="timestamp"):
        normalize_cloudtrail([cloudtrail_event(eventTime="")])


def test_synthetic_marker_is_explicit() -> None:
    by_default = normalize_cloudtrail([cloudtrail_event()])
    marked = normalize_cloudtrail([cloudtrail_event()], synthetic=True)
    assert by_default[0].synthetic is False
    assert marked[0].synthetic is True


def test_config_source_is_validated() -> None:
    with pytest.raises(ValueError, match="unsupported audit source"):
        AuditSourceConfig(source="gcp_cloud_audit")
    with pytest.raises(ValueError, match="aws_cloudtrail"):
        normalize_cloudtrail(
            [cloudtrail_event()],
            AuditSourceConfig(source="github_audit"),
        )
