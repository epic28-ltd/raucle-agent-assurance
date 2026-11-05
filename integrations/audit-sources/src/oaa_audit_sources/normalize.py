# SPDX-License-Identifier: Apache-2.0
"""K2 audit-source normalizers: exported JSON -> v1 AuditCandidate records.

Offline by design (ADR-0004 vantage point A): the caller supplies audit
events that were ALREADY exported (e.g. from a CloudTrail Lake query result
or a GitHub audit log export). Nothing in this package performs I/O, DNS or
HTTP; collectors/fetchers remain deployment glue (see README and
``docs/spikes/K2-findings.md``).

Payload discipline (invariant from ADR-0002/0003 spirit): a candidate never
carries raw payloads. ``raw_ref`` holds ONLY the fields the deployment's
``AuditSourceConfig.declared_raw_fields`` allows; everything else is dropped
here at normalize time, not downstream.

Synthetic markers: ``AuditCandidate.synthetic`` is an explicit marker for
hand-built test records; evidence that is not marked synthetic must have come
from a real export. Mirrors ``ReceiptRecord.synthetic`` in oaa_correlation.

GitHub linkage honesty (research round-2 finding): GitHub audit events carry
NO client-supplied correlation field, and ``request_id`` is GitHub-internal
(we cannot verify what it refers to) — it is recorded ONLY as
``unverified_linkage`` text and is never eligible for correlation. Binding
matches use the per-receipt token convention instead: the gate records the
fingerprint (``hashed_token``) of the credential it issued alongside the
receipt, and the audit event carries the same fingerprint.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field

SUPPORTED_SOURCES = ("aws_cloudtrail", "github_audit")

ISO_Z_SUFFIX = "+00:00"

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _snake(name: str) -> str:
    """RunInstances -> run_instances."""
    return _CAMEL_BOUNDARY.sub("_", name).replace("-", "_").lower()


# Research-derived default map for CloudTrail eventNames whose normalized op
# is NOT simply ``service.snake_case(eventName)`` (e.g. API names that differ
# from the control-plane concept, or service prefixes that must stay exact).
CLOUDTRAIL_OP_MAP: dict[str, str] = {
    "GetObject": "s3.get_object",
    "PutObject": "s3.put_object",
    "DeleteObject": "s3.delete_object",
    "RunInstances": "ec2.run_instances",
    "TerminateInstances": "ec2.terminate_instances",
    "AssumeRole": "sts.assume_role",
    "GetSecretValue": "secretsmanager.get_secret_value",
    "InvokeFunction": "lambda.invoke",
}


@dataclass(frozen=True)
class AuditSourceConfig:
    """Per-source normalize configuration.

    ``declared_raw_fields`` is the ONLY passthrough contract for ``raw_ref``:
    keys outside this tuple are dropped from the source event and never reach
    a candidate. Default declarations for each source exclude payloads
    (``requestParameters`` and friends stay out unless a deployment explicitly
    declares them — which would be an auditable config change).
    """

    source: str
    declared_raw_fields: tuple[str, ...] = ()
    op_map: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        if self.source not in SUPPORTED_SOURCES:
            raise ValueError(
                f"unsupported audit source: {self.source!r} (known: {SUPPORTED_SOURCES})"
            )

    def declared(self, event: Mapping[str, object]) -> dict[str, object]:
        """Config-declared subset of ``event``, presence-checked (no invented keys)."""
        return {
            f: event[f]
            for f in self.declared_raw_fields
            if f in event  # type: ignore[index]
        }


def _utc_iso(raw: object, source: str, event_id: str) -> str:
    if not isinstance(raw, str) or not raw:
        raise ValueError(
            f"{source} event {event_id!r} has no parsable timestamp field "
            "(exports must retain event time)"
        )
    text = raw.replace("Z", ISO_Z_SUFFIX)
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:  # pragma: no cover - message only
        raise ValueError(f"{source} event {event_id!r} has unparsable timestamp {raw!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.UTC)
    return parsed.astimezone(dt.UTC).isoformat().replace(ISO_Z_SUFFIX, "Z")


@dataclass(frozen=True)
class AuditCandidate:
    """v1 candidate record raised from one tool-side audit event.

    ``session_binding`` — the deployment-specific linkage token carried by the
    event itself:    AWS = roleSessionName (gate-set ``oaa-<receipt_hash_prefix>``
    convention) preferred, or STS sourceIdentity in its absence; GitHub =
    the token fingerprint (``hashed_token``) or ``None``.

    ``unverified_linkage`` — identifiers present in the event that we CANNOT
    verify (GitHub-internal ``request_id``). Never used for correlation.

    ``raw_ref`` — only ``AuditSourceConfig.declared_raw_fields`` keys. No
    payloads beyond the configuration contract.
    """

    source: str
    source_event_id: str
    event_time: str  # UTC ISO-8601, 'Z' suffix
    actor: str | None
    action: str
    resource: str | None
    session_binding: str | None
    unverified_linkage: str | None = None
    raw_ref: dict[str, object] = field(default_factory=dict)
    synthetic: bool = False  # explicit marker: hand-built record, NOT exported evidence

    def __post_init__(self) -> None:
        if self.source not in SUPPORTED_SOURCES:
            raise ValueError(f"unknown source: {self.source!r}")
        if not self.source_event_id:
            raise ValueError("source_event_id is required")
        # round-trip check guards the UTC-ISO contract
        dt.datetime.fromisoformat(self.event_time.replace("Z", ISO_Z_SUFFIX))


def _cloudtrail_actor(user_identity: dict[str, object]) -> tuple[str | None, str | None]:
    """(actor, session_binding) from a CloudTrail userIdentity block.

    Binding preference: role session name (the gate-set
    ``oaa-<receipt_hash_prefix>`` token) > STS sourceIdentity — the binding
    token to match on is the one the gate SET, so the session name wins even
    when a deployment also sets sourceIdentity. Actor preference:
    sourceIdentity > userName > principal prefix.
    """
    principal = user_identity.get("principalId")
    principal = principal if isinstance(principal, str) else ""
    session_context = user_identity.get("sessionContext")
    session_context = session_context if isinstance(session_context, dict) else {}
    source_identity = session_context.get("sourceIdentity")
    source_identity = source_identity if isinstance(source_identity, str) else None

    session_name: str | None = None
    if ":" in principal:
        session_name = principal.split(":", 1)[1] or None
    elif "." in principal:
        session_name = principal.split(".", 1)[1] or None

    user_name = user_identity.get("userName")
    actor: str | None = source_identity or (
        user_name if isinstance(user_name, str) and user_name else None
    )
    if actor is None and principal:
        actor = principal.split(":", 1)[0]
    binding = session_name if session_name else source_identity
    return actor, binding


def _resource_from_cloudtrail(event: Mapping[str, object]) -> str | None:
    resources = event.get("resources")
    if isinstance(resources, list):
        for entry in resources:
            if isinstance(entry, dict) and entry.get("resourceName"):
                rtype = entry.get("resourceType") or ""
                name = entry["resourceName"]
                return f"{rtype}/{name}" if rtype else str(name)
    return None


def normalize_cloudtrail(
    events: list[dict[str, object]],
    config: AuditSourceConfig | None = None,
    *,
    synthetic: bool = False,
) -> list[AuditCandidate]:
    """Normalize exported CloudTrail management events into candidates.

    Field mapping (see docs/spikes/K2-findings.md for the full table):
    eventID -> source_event_id; eventTime (UTC ISO) -> event_time;
    userIdentity.sessionContext -> session_binding + actor; eventName +
    eventSource -> normalized op; resources -> resource.
    """
    cfg = config or AuditSourceConfig(
        source="aws_cloudtrail",
        declared_raw_fields=("eventSource", "recipientAccountId", "awsRegion"),
    )
    if cfg.source != "aws_cloudtrail":
        raise ValueError("config must describe aws_cloudtrail")
    op_map = dict(CLOUDTRAIL_OP_MAP)
    if cfg.op_map:
        op_map.update(cfg.op_map)

    candidates: list[AuditCandidate] = []
    for event in events:
        event_id = str(event.get("eventID") or event.get("EventId") or "")
        if not event_id:
            raise ValueError("CloudTrail event without eventID cannot be referenced")
        event_time = _utc_iso(event.get("eventTime"), cfg.source, event_id)

        user_identity = event.get("userIdentity")
        user_identity = user_identity if isinstance(user_identity, dict) else {}
        actor, binding = _cloudtrail_actor(user_identity)

        service = str(event.get("eventSource") or "").split(".")[0]
        event_name = str(event.get("eventName") or "")
        action = op_map.get(event_name) or (
            f"{service}.{_snake(event_name)}" if service else _snake(event_name)
        )

        candidates.append(
            AuditCandidate(
                source=cfg.source,
                source_event_id=event_id,
                event_time=event_time,
                actor=actor,
                action=action,
                resource=_resource_from_cloudtrail(event),
                session_binding=binding,
                raw_ref=cfg.declared(event),
                synthetic=synthetic,
            )
        )
    return candidates


@dataclass(frozen=True)
class _GithubIdentity:
    actor: str
    binding: str | None
    unverified: str | None


def _github_actor(event: Mapping[str, object]) -> _GithubIdentity:
    actor = str(event.get("actor") or "")
    hashed_token = event.get("hashed_token")
    binding = hashed_token if isinstance(hashed_token, str) and hashed_token else None
    request_id = event.get("request_id")
    unverified = None
    if request_id:
        # GitHub-internal identifier: recorded as UNVERIFIABLE linkage only.
        unverified = f"github.request_id:{request_id}"
    return _GithubIdentity(actor=actor, binding=binding, unverified=unverified)


def _github_repo(event: Mapping[str, object]) -> str | None:
    repo = event.get("repo")
    if isinstance(repo, str):
        return repo or None
    if isinstance(repo, dict):
        return str(repo.get("name")) if repo.get("name") else None
    return None


def normalize_github(
    events: list[dict[str, object]],
    config: AuditSourceConfig | None = None,
    *,
    synthetic: bool = False,
) -> list[AuditCandidate]:
    """Normalize exported GitHub audit-log events into candidates.

    ``source_event_id``: ``_id`` when the export carries the streaming row id,
    otherwise a deterministic digest over (actor, repo, action, time fields).
    ``created_at`` is the fallback time field when ``@timestamp`` is absent.
    Binding = ``hashed_token`` fingerprint or ``None``; ``request_id`` is
    recorded as unverified linkage and NEVER used for correlation.
    """
    cfg = config or AuditSourceConfig(
        source="github_audit",
        declared_raw_fields=(
            "actor_is_bot",
            "actor_is_agent",
            "token_scopes",
            "programmatic_access_type",
            "integration",
            "application_client_id",
            "business_category",
        ),
    )
    if cfg.source != "github_audit":
        raise ValueError("config must describe github_audit")

    candidates: list[AuditCandidate] = []
    for event in events:
        raw_time = event.get("@timestamp") or event.get("created_at")
        actor = str(event.get("actor") or "")
        action = str(event.get("action") or "").lower()
        digest_seed = "|".join(
            (
                actor,
                _github_repo(event) or "",
                action,
                str(event.get("@timestamp") or ""),
                str(event.get("created_at") or ""),
            )
        )
        event_id = str(event.get("_id") or "")
        if not event_id:
            event_id = "sha256:" + hashlib.sha256(digest_seed.encode("utf-8")).hexdigest()[:16]
        event_time = _utc_iso(raw_time, cfg.source, event_id)
        if not actor or not action:
            raise ValueError(f"GitHub audit event {event_id!r} lacks actor/action")
        ident = _github_actor(event)

        candidates.append(
            AuditCandidate(
                source=cfg.source,
                source_event_id=event_id,
                event_time=event_time,
                actor=ident.actor,
                action=action,
                resource=_github_repo(event),
                session_binding=ident.binding,
                unverified_linkage=ident.unverified,
                raw_ref=cfg.declared(event),
                synthetic=synthetic,
            )
        )
    return candidates
