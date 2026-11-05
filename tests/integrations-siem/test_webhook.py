# SPDX-License-Identifier: Apache-2.0
"""EXP-01 tests: generic SIEM webhook envelope, retry/dedup/dead-letter, receiver idempotency.

All network is an in-process dummy HTTP server (no internet).
"""

from __future__ import annotations

import datetime as dt
import http.server
import json
import threading
from pathlib import Path
from typing import ClassVar

import pytest
from integrations.siem.webhook import (
    ENVELOPE_VERSION,
    DeadLetterSink,
    DedupStore,
    EventInputs,
    IdempotentCollector,
    WebhookConfig,
    build_envelope,
    compute_event_id,
    deliver,
    load_config,
)

SECRET_AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
FIXTURE_TOKEN_SECRET = "ghp_0000000000000000000000000000000000000000secret"

AT = dt.datetime(2026, 11, 4, 12, 0, 0, tzinfo=dt.UTC)
BASIS = dict(
    kind="finding",
    org_id="org-0000",
    agent_id="agent-alpha",
    run_ref="run-2026-11-04-0001",
    trace_ref="trace-abc",
    receipt_hash="sha256:" + "0" * 64,
    event_time=AT,
)


def make_envelope(**overrides) -> dict:
    basis: dict = dict(BASIS)
    fields: dict = {
        "rule_id": "SEC-001",
        "rule_version": "1",
        "severity": "high",
        "confidence": "high",
        "evidence_refs": ["ev-1"],
        "subject": "agent-alpha/shell",
        "suppression_reason": None,
    }
    if "fields" in overrides:
        fields.update(overrides.pop("fields"))
    explanation = overrides.pop("explanation", "ok")
    basis.update(overrides)
    return build_envelope(EventInputs(**basis, fields=fields), explanation=explanation)


# ------------------------------------------------------------- envelope ----


def test_envelope_stability_two_runs_same_event_id():
    env_a, env_b = make_envelope(), make_envelope()
    assert env_a["event_id"] == env_b["event_id"]
    assert env_a == env_b
    # deterministic UUIDv5 over canonical inputs
    assert env_a["event_id"] == compute_event_id(
        EventInputs(
            **BASIS,
            fields=json.loads(
                json.dumps(
                    {
                        "rule_id": "SEC-001",
                        "rule_version": "1",
                        "severity": "high",
                        "confidence": "high",
                        "evidence_refs": ["ev-1"],
                        "subject": "agent-alpha/shell",
                        "suppression_reason": None,
                    }
                )
            ),
        )
    )
    # a materially different event gets a different id
    other = make_envelope(
        fields={
            "rule_id": "SEC-002",
            "rule_version": "1",
            "severity": "high",
            "confidence": "high",
            "evidence_refs": [],
            "subject": None,
            "suppression_reason": None,
        }
    )
    assert other["event_id"] != env_a["event_id"]
    assert env_a["envelope_version"] == ENVELOPE_VERSION == "1"


def test_envelope_structure_required_top_level_keys():
    env = make_envelope()
    for key in (
        "envelope_version",
        "event_id",
        "event_time",
        "kind",
        "org_id",
        "agent_id",
        "run_ref",
        "trace_ref",
        "receipt_hash",
        "fields",
    ):
        assert key in env
    assert env["event_time"].endswith("Z")
    assert env["fields"]["rule_id"] == "SEC-001"


def test_no_secret_in_envelope():
    env = make_envelope(
        explanation=(
            f"credential {SECRET_AWS_KEY} leaked via shell; lease used bearer "
            f"bearer {FIXTURE_TOKEN_SECRET} at 12:00Z"
        )
    )
    text = json.dumps(env)
    assert SECRET_AWS_KEY not in text
    assert FIXTURE_TOKEN_SECRET not in text
    assert "<redacted:aws_access_key>" in json.dumps(env["fields"])
    # the placeholder carries only a pattern name, never matched material
    placeholder_text = json.dumps(env["fields"])
    assert "leaked" in placeholder_text and SECRET_AWS_KEY not in placeholder_text


def test_env_builder_rejects_payload_keys():
    with pytest.raises(ValueError, match="forbidden payload-bearing key"):
        make_envelope(
            fields={
                "payload": {"x": 1},
                "rule_id": "SEC-001",
                "rule_version": "1",
                "severity": "high",
                "confidence": "high",
                "evidence_refs": [],
                "subject": None,
                "suppression_reason": None,
            }
        )


# ------------------------------------------------------------ delivery -----


@pytest.fixture()
def config_factory(tmp_path: Path):
    def factory(url: str, **overrides) -> tuple[WebhookConfig, Path, Path]:
        allow_http = overrides.pop("allow_http", url.startswith("http://"))
        dedup_path = tmp_path / "dedup.json"
        dl_path = tmp_path / "dead-letter.jsonl"
        cfg = WebhookConfig(
            url=url,
            org_id="org-0000",
            allow_http=allow_http,
            dedup_state_path=str(dedup_path),
            dead_letter_path=str(dl_path),
            **overrides,
        )
        return cfg, dedup_path, dl_path

    return factory


class _Handler(http.server.BaseHTTPRequestHandler):
    fail_next: ClassVar[list[int]] = []  # class-level mutable, reset per test
    received: ClassVar[list[dict]] = []
    status_all: int = 200
    lock = threading.Lock()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        with _Handler.lock:
            _Handler.received.append(json.loads(body))
            if _Handler.fail_next and _Handler.fail_next[0] > 0:
                _Handler.fail_next[0] -= 1
                code, retry = 500, True
            else:
                code, retry = _Handler.status_all, False
        self.send_response(code)
        self.end_headers()
        if retry or 400 <= code < 600:
            self.wfile.write(b'"error"')

    def log_message(self, *args):  # silence
        pass


@pytest.fixture()
def server():
    _Handler.fail_next = []
    _Handler.received = []
    _Handler.status_all = 200
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_port}/events"
    httpd.shutdown()


def _deliver(env, cfg, factory):
    cfg2, dedup_path, dl_path = factory(cfg.url)
    dedup = DedupStore(dedup_path)
    return deliver(
        env, cfg2, dedup=dedup, dead_letter=DeadLetterSink(dl_path), sleep=lambda s: None
    )


def bare_config(url, **kw):
    return WebhookConfig(url=url, org_id="org-0000", **kw)


def test_retry_then_success(server, config_factory):
    env = make_envelope()
    _Handler.fail_next = [2]
    outcome = _deliver(env, bare_config(server), config_factory)
    assert outcome.status == "sent"
    assert outcome.attempts == 3
    assert len(_Handler.received) == 3  # each retry delivers the same envelope
    assert all(r["event_id"] == env["event_id"] for r in _Handler.received)


def test_dead_letter_after_exhaustion(server, config_factory, tmp_path):
    env = make_envelope(
        fields=json.loads(
            json.dumps(
                {
                    "rule_id": "SEC-001",
                    "rule_version": "1",
                    "severity": "high",
                    "confidence": "high",
                    "evidence_refs": [],
                    "subject": None,
                    "suppression_reason": None,
                }
            )
        )
    )
    _Handler.status_all = 500
    outcome = _deliver(env, bare_config(server, max_attempts=4), config_factory)
    assert outcome.status == "dead_lettered"
    assert outcome.attempts == 4
    assert len(_Handler.received) == 4
    _cfg2, _, dl_path = config_factory(server)
    rows = [json.loads(line) for line in dl_path.read_text().splitlines()]
    assert len(rows) == 1
    assert rows[0]["envelope"]["event_id"] == env["event_id"]
    assert "HTTP 500" in rows[0]["error"]
    # a dead-lettered event is NOT marked sent: a later config can retry it
    cfg3, dedup_path, _ = config_factory(server)
    _Handler.status_all = 200
    outcome2 = deliver(env, cfg3, dedup=DedupStore(dedup_path), sleep=lambda s: None)
    assert outcome2.status == "sent"


def test_4xx_dead_letters_without_retry(server, config_factory):
    env = make_envelope()
    _Handler.status_all = 400
    outcome = _deliver(env, bare_config(server), config_factory)
    assert outcome.status == "dead_lettered"
    assert outcome.attempts == 1
    assert len(_Handler.received) == 1


# ---------------------------------------------------------------- dedup ----


def test_dedup_persisted_across_exporter_instances(server, config_factory, tmp_path):
    env = make_envelope()
    _, dedup_path, _ = config_factory(server)
    cfg, _, _ = config_factory(server)
    first = deliver(env, cfg, dedup=DedupStore(dedup_path), sleep=lambda s: None)
    assert first.status == "sent"
    # fresh DedupStore, same state file (simulating a restarted exporter)
    cfg2, _, _ = config_factory(server)
    second = deliver(env, cfg2, dedup=DedupStore(dedup_path), sleep=lambda s: None)
    assert second.status == "deduplicated"
    assert len(_Handler.received) == 1
    state = json.loads(Path(cfg.dedup_state_path).read_text())
    assert env["event_id"] in state["event_ids"]


def test_receiver_idempotent_merge(server, config_factory):
    env = make_envelope()
    collector = IdempotentCollector()
    # at-least-once transport: same envelope delivered twice
    assert collector.accept(env) == "accepted"
    assert collector.accept(json.loads(json.dumps(env))) == "duplicate"
    other = make_envelope(
        fields={
            "rule_id": "SEC-002",
            "rule_version": "1",
            "severity": "low",
            "confidence": "medium",
            "evidence_refs": [],
            "subject": None,
            "suppression_reason": None,
        }
    )
    assert collector.accept(other) == "accepted"
    assert collector.deliveries == 3
    assert len(collector.events) == 2


def test_receiver_path_over_transport(server, config_factory):
    """End-to-end: retry storm + redelivery, receiver still merges to one event."""
    env = make_envelope()
    _Handler.fail_next = [3]
    outcome = _deliver(env, bare_config(server), config_factory)
    assert outcome.status == "sent"
    # transport redelivers one duplicate (at-least-once)
    collector = IdempotentCollector()
    for body in _Handler.received:
        collector.accept(body)
    collector.accept(env)  # and one late duplicate
    assert collector.deliveries == len(_Handler.received) + 1
    assert len(collector.events) == 1


# ---------------------------------------------------------------- config ---


def test_load_config_yaml_and_schema(tmp_path):
    cfg = load_config("integrations/siem/config/webhook.yaml")
    assert cfg.version == "1"
    assert cfg.org_id == "org-0000"
    assert cfg.allow_http is False
    # env override wins; endpoint is env/config only
    overridden = load_config(
        "integrations/siem/config/webhook.yaml", env_url="https://siem.example/hook"
    )
    assert overridden.url == "https://siem.example/hook"


def test_https_enforced(tmp_path):
    cfg = WebhookConfig(url="http://siem.example/hook", org_id="org-0000")
    dedup = DedupStore(tmp_path / "d.json")
    with pytest.raises(ValueError, match="https"):
        deliver(make_envelope(), cfg, dedup=dedup, sleep=lambda s: None)
    # unknown kind and missing ids fail closed
    with pytest.raises(ValueError, match="unknown outbound event kind"):
        build_envelope(EventInputs(**dict(BASIS, kind="trace"), fields={}))


def test_build_envelope_requires_org_and_agent_id():
    with pytest.raises(ValueError, match="org_id and agent_id"):
        build_envelope(EventInputs(**dict(BASIS, org_id=""), fields={}))
