# SPDX-License-Identifier: Apache-2.0
"""Open Agent Assurance — generic SIEM webhook exporter (EXP-01).

Emits a stable, versioned outbound event envelope (``envelope_version: "1"``)
over plain HTTP(S) POST JSON. Design invariants:

- **No secrets, no raw content, no payloads.** Only index-plane fields
  (identifiers, hashes, states, severities) travel. Finding explanations may
  carry redacted placeholders only (``<redacted:name>``); the builder rejects
  any envelope containing payload-bearing key names.
- **Stable event identity.** ``event_id`` is a deterministic UUIDv5 over the
  canonical JSON of every envelope input. Two builds of the same event —
  same inputs, same order of calls — yield the same ``event_id``.
- **At-least-once transport, envelope dedup at receiver.** The sender
  retries transient failures with bounded backoff, then writes to a
  dead-letter JSONL sink. Already-sent ``event_id``s are persisted to a small
  state file so restarts do not re-send. Receivers must merge idempotently by
  ``event_id`` (``IdempotentCollector`` is the reference in-process merge).
- **TLS/URL from env/config only.** The endpoint URL is never hard-coded;
  ``https`` is required by default (``allow_http`` opt-in for localhost
  fixtures only). Credentials belong to the transport layer and are NEVER
  placed in the envelope.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path

ENVELOPE_VERSION = "1"

EVENT_KINDS = ("finding", "verification", "correlation", "evidence_summary")

# Payload-bearing key names that must never appear anywhere in an envelope.
FORBIDDEN_KEYS = frozenset(
    {
        "payload",
        "content",
        "raw",
        "raw_content",
        "jws",
        "secret",
        "secrets",
        "password",
        "token",
        "credential",
        "credentials",
        "api_key",
        "apikey",
        "authorization",
        "env",
        "environment",
    }
)

# Secret-shaped material redacted from explanations, in the RULE-01 spirit
# (SEC-008 patterns, table-driven). Anything matching becomes a placeholder.
REDACT_PATTERNS: dict[str, str] = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "bearer_token": r"(?i:bearer\s+)[A-Za-z0-9._\-]{16,}",
    "pem_private_key": r"-----BEGIN [A-Z ]*PRIVATE KEY-----[^-]*-----END [A-Z ]*PRIVATE KEY-----",
    "generic_secret_kv": r"(?i:(?:password|passwd|secret|token)\s*[=:]\s*)\S{4,}",
    "long_hex_secret": r"\b[a-fA-F0-9]{32,}\b",
}

PLACEHOLDER_PREFIX = "<redacted:"
PLACEHOLDER_SUFFIX = ">"


def _canonical(obj: object) -> str:
    """Canonical JSON: sorted keys, tight separators (determinism basis)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _redact(text: str) -> str:
    """Replace secret-shaped spans with named redacted placeholders."""
    out = text
    for name, pattern in REDACT_PATTERNS.items():
        out = re.sub(pattern, PLACEHOLDER_PREFIX + name + PLACEHOLDER_SUFFIX, out)
    return out


def _assert_no_payload(obj: object) -> None:
    """Fail-closed: no forbidden key anywhere in the serialized envelope."""
    text = _canonical(obj)
    # forbid keys; placeholder tokens inside *values* are allowed (they are
    # the only way finding explanations carry secret references)
    lowered = text.lower()
    for key in FORBIDDEN_KEYS:
        if f'"{key}"' in lowered:
            raise ValueError(f"forbidden payload-bearing key in envelope: {key!r}")
    # canonical bytes and secrets never pass through this builder; belt+braces
    if "\\u0000" in text:
        raise ValueError("NUL escape in envelope")


def _utc_rfc3339(event_time: dt.datetime | None) -> str:
    if event_time is None:
        return ""
    at = event_time if event_time.tzinfo else event_time.replace(tzinfo=dt.UTC)
    return at.astimezone(dt.UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


# ---------------------------------------------------------------- envelope ---


@dataclass(frozen=True)
class EventInputs:
    """Canonical inputs of one outbound event (all envelope input is here)."""

    kind: str
    org_id: str
    agent_id: str
    run_ref: str
    trace_ref: str
    receipt_hash: str | None
    event_time: dt.datetime
    fields: dict[str, object]


def compute_event_id(inputs: EventInputs) -> str:
    """Deterministic UUIDv5 over the canonical JSON of the envelope inputs."""
    basis = {
        "envelope_version": ENVELOPE_VERSION,
        "kind": inputs.kind,
        "org_id": inputs.org_id,
        "agent_id": inputs.agent_id,
        "run_ref": inputs.run_ref,
        "trace_ref": inputs.trace_ref,
        "receipt_hash": inputs.receipt_hash or "",
        "event_time": _utc_rfc3339(inputs.event_time),
        "fields": inputs.fields,
    }
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "oaa:siem:event:" + _canonical(basis)))


def build_envelope(
    inputs: EventInputs,
    *,
    explanation: str | None = None,
) -> dict[str, object]:
    """Build the stable outbound envelope. Fail-closed on payload keys.

    ``explanation`` (finding kind only) is redacted to placeholders before it
    is placed under ``fields["explanation"]``.
    """
    if inputs.kind not in EVENT_KINDS:
        raise ValueError(f"unknown outbound event kind: {inputs.kind!r}")
    if not inputs.org_id or not inputs.agent_id:
        raise ValueError("org_id and agent_id are required")
    fields = dict(inputs.fields)
    if explanation is not None:
        if inputs.kind != "finding":
            raise ValueError(f"explanation is only accepted for kind finding: {inputs.kind!r}")
        if "explanation" in fields:
            raise ValueError("pass finding explanations via `explanation=`, not via fields")
        fields["explanation"] = _redact(explanation)
    envelope: dict[str, object] = {
        "envelope_version": ENVELOPE_VERSION,
        "event_id": compute_event_id(inputs),
        "event_time": _utc_rfc3339(inputs.event_time),
        "kind": inputs.kind,
        "org_id": inputs.org_id,
        "agent_id": inputs.agent_id,
        "run_ref": inputs.run_ref,
        "trace_ref": inputs.trace_ref,
        "receipt_hash": inputs.receipt_hash,
        "fields": fields,
    }
    _assert_no_payload(envelope)
    return envelope


# ----------------------------------------------------------- dedup + sinks ---


@dataclass
class DedupStore:
    """Small persisted state file of sent event_ids (FIFO-capped)."""

    path: Path
    capacity: int = 10_000
    seen: set[str] = field(default_factory=set)
    order: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        if self.path.exists():
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self.order = list(raw.get("event_ids", []))[-self.capacity :]
            self.seen = set(self.order)

    def seen_before(self, event_id: str) -> bool:
        return event_id in self.seen

    def mark_sent(self, event_id: str) -> None:
        if event_id in self.seen:
            return
        self.seen.add(event_id)
        self.order.append(event_id)
        if len(self.order) > self.capacity:
            drop = len(self.order) - self.capacity
            self.order = self.order[drop:]
            self.seen = set(self.order)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"event_ids": self.order}, separators=(",", ":")),
            encoding="utf-8",
        )


@dataclass
class DeadLetterSink:
    """Bounded-nothing JSONL dead-letter file sink."""

    path: Path

    def write(self, envelope: dict[str, object], error: str, attempts: int) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        row = {
            "at": _utc_rfc3339(dt.datetime.now(dt.UTC)),
            "attempts": attempts,
            "error": error,
            "envelope": envelope,
        }
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(_canonical(row) + "\n")


@dataclass
class IdempotentCollector:
    """Reference receiver-side merge: idempotent by ``event_id``.

    A real SIEM receiver (or forwarding pipeline) must behave like this:
    the same envelope delivered twice produces ONE stored event.
    """

    events: list[dict[str, object]] = field(default_factory=list)
    seen: set[str] = field(default_factory=set)
    deliveries: int = 0

    def accept(self, envelope: dict[str, object]) -> str:
        self.deliveries += 1
        event_id = str(envelope["event_id"])
        if event_id in self.seen:
            return "duplicate"
        self.seen.add(event_id)
        self.events.append(dict(envelope))
        return "accepted"


# ------------------------------------------------------------- delivery ------


@dataclass
class WebhookConfig:
    """Exporter configuration (file-backed; see config/webhook.yaml)."""

    url: str
    org_id: str
    max_attempts: int = 4
    backoff_base_seconds: float = 0.5
    timeout_seconds: float = 5.0
    dedup_state_path: str = "state/siem-dedup.json"
    dead_letter_path: str = "state/siem-dead-letter.jsonl"
    dedup_capacity: int = 10_000
    allow_http: bool = False
    version: str = "1"


@dataclass
class DeliveryOutcome:
    status: str  # sent | deduplicated | dead_lettered
    event_id: str
    attempts: int
    error: str | None = None


def validate_endpoint(url: str, *, allow_http: bool) -> None:
    if allow_http:
        return
    if not url.startswith("https://"):
        raise ValueError("webhook endpoint must be https:// (allow_http to override)")


def deliver(
    envelope: dict[str, object],
    config: WebhookConfig,
    *,
    dedup: DedupStore,
    dead_letter: DeadLetterSink | None = None,
    sleep: callable = time.sleep,  # type: ignore[assignment]
    opener: callable = urllib.request.urlopen,  # type: ignore[assignment]
) -> DeliveryOutcome:
    """POST one envelope with bounded retry/backoff; dead-letter on exhaustion.

    Transport is at-least-once: every accepted attempt may be re-delivered,
    so the receiver merges idempotently by ``event_id``. The sender-side
    dedup store prevents re-sending already-confirmed events across runs.
    Non-retryable client errors (4xx except 429) dead-letter immediately.
    """
    event_id = str(envelope["event_id"])
    validate_endpoint(config.url, allow_http=config.allow_http)
    if dedup.seen_before(event_id):
        return DeliveryOutcome("deduplicated", event_id, 0)
    body = _canonical(envelope).encode("utf-8")
    request = urllib.request.Request(
        config.url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    last_error = ""
    attempts = 0
    for attempt in range(1, config.max_attempts + 1):
        attempts = attempt
        outcome, last_error, retryable = _attempt_delivery(
            opener, request, config, dedup, event_id, attempt
        )
        if outcome is not None:
            return outcome
        if not retryable:
            break  # non-retryable
        if attempt < config.max_attempts:
            sleep(config.backoff_base_seconds * (2 ** (attempt - 1)))
    if dead_letter is not None:
        dead_letter.write(envelope, last_error, attempts)
    return DeliveryOutcome("dead_lettered", event_id, attempts, last_error)


def _attempt_delivery(
    opener, request, config: WebhookConfig, dedup: DedupStore, event_id: str, attempt: int
) -> tuple[DeliveryOutcome | None, str, bool]:
    """One POST attempt. Returns (sent-outcome-or-None, last_error, retryable)."""
    try:
        with opener(request, timeout=config.timeout_seconds) as response:
            response.read()
            status = getattr(response, "status", 200)
        if 200 <= status < 300:
            dedup.mark_sent(event_id)
            return DeliveryOutcome("sent", event_id, attempt), "", False
        raise urllib.error.URLError(f"unexpected status {status}")
    except urllib.error.HTTPError as exc:
        code = exc.code
        return None, f"HTTP {code}", not (400 <= code < 500 and code != 429)
    except OSError as exc:
        return None, str(exc) or type(exc).__name__, True


# ------------------------------------------------------------ config loading -


def load_config(path: str | Path, *, env_url: str | None = None) -> WebhookConfig:
    """Load versioned webhook config YAML (schema v1). Requires PyYAML.

    ``env_url`` (e.g. the ``OAA_SIEM_WEBHOOK_URL`` environment variable)
    overrides the file's ``url`` — the endpoint is env/config only.
    Credentials are NEVER part of this config; they belong to the transport.
    """
    import yaml  # noqa: PLC0415
    # yaml is an optional dependency: config-loading convenience only.

    with open(path, encoding="utf-8") as fh:
        raw = yaml.safe_load(fh)
    if not isinstance(raw, dict):
        raise ValueError("webhook config must be a mapping")
    if raw.get("version") != 1:
        raise ValueError(f"unsupported webhook-config version: {raw.get('version')!r}")
    url = env_url or raw.get("url") or ""
    return WebhookConfig(
        url=str(url),
        org_id=str(raw.get("org_id", "")),
        max_attempts=int(raw.get("max_attempts", 4)),
        backoff_base_seconds=float(raw.get("backoff_base_seconds", 0.5)),
        timeout_seconds=float(raw.get("timeout_seconds", 5.0)),
        dedup_state_path=str(raw.get("dedup_state_path", "state/siem-dedup.json")),
        dead_letter_path=str(raw.get("dead_letter_path", "state/siem-dead-letter.jsonl")),
        dedup_capacity=int(raw.get("dedup_capacity", 10_000)),
        allow_http=bool(raw.get("allow_http", False)),
        version="1",
    )
