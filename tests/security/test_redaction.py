# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Open Agent Assurance contributors
"""PRIV-01 unit tests: redaction patterns, allowlist, entropy bounds,
collector scan/quarantine. All runnable WITHOUT the Langfuse stack
(the live-leak proof is in test_priv01_live.py and skips cleanly offline)."""

from __future__ import annotations

import json
import pathlib
import sys

import pytest
from oaa_instrumentation.redaction import (
    Redactor,
    ScanReport,
    quarantine,
    replacement_token,
    scan_batch,
    shannon_entropy_per_char,
)

FIXTURES = pathlib.Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="module")
def redactor() -> Redactor:
    return Redactor.from_yaml()


@pytest.fixture(scope="module")
def seeds() -> dict[str, dict]:
    raw = json.loads((FIXTURES / "seeds" / "seeds.json").read_text(encoding="utf-8"))["seeds"]
    return {s["id"]: s for s in raw}


# ---------------------------------------------------------------- table-driven
SENSITIVE_CASES = [
    # (case_id, attr_key, sample, expected_class, expected_pattern)
    (
        "aws-access-key-id",
        "aws.access_key",
        "AKIAIOSFODNN7EXAMPLE",
        "aws_access_key",
        "aws_access_key_id",
    ),
    (
        "bearer-authorization",
        "http.request.header.authorization",
        "Bearer c8f1e0d7aa4419be23",
        "bearer_token",
        "bearer_token",
    ),
    (
        "jwt-three-segments",
        "oidc.token",
        "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SIG_VALUE_XYZ",
        "jwt",
        "jwt",
    ),
    (
        "pem-private-key",
        "tls.client_key_pem",
        "-----BEGIN RSA PRIVATE KEY-----\nAbCd\n-----END RSA PRIVATE KEY-----",
        "private_key_pem",
        "private_key_pem",
    ),
    (
        "pem-ec-private-key",
        "tls.node_key.pem",
        "-----BEGIN EC PRIVATE KEY-----\nAbCdEf\n-----END EC PRIVATE KEY-----",
        "private_key_pem",
        "private_key_pem",
    ),
    ("email", "user.email", "agent.operator@example.com", "email", "email"),
    (
        "credential-kv-api-key",
        "llm.tools.input",
        "api_key=sk-tolive-51eb0e9c9f11",
        "credential_kv",
        "credential_kv",
    ),
    (
        "credential-kv-password",
        "db.connect.echo",
        "password=Zx91QuR7bLmN",
        "credential_kv",
        "credential_kv",
    ),
]


@pytest.mark.parametrize(
    ("case_id", "key", "value", "exp_class", "exp_pattern"),
    SENSITIVE_CASES,
    ids=[c[0] for c in SENSITIVE_CASES],
)
def test_pattern_table_redacts(
    redactor: Redactor, case_id: str, key: str, value: str, exp_class: str, exp_pattern: str
) -> None:
    scrubbed, violations = redactor.redact({key: value})
    token = scrubbed[key]
    assert token.startswith("[REDACTED:"), token
    assert exp_class in token
    assert "len=" in token
    assert value not in token
    assert [v.pattern_id for v in violations] == [exp_pattern]
    assert all(v.privacy_class == exp_class for v in violations)
    # the original secret must not survive anywhere in the scrubbed mapping
    assert value not in json.dumps(scrubbed)


def test_replacement_carries_length_only(redactor: Redactor) -> None:
    value = "Bearer " + "a1" * 20
    scrubbed, violations = redactor.redact({"h": value})
    assert scrubbed["h"] == replacement_token("bearer_token", len("Bearer " + "a1" * 20))
    v = violations[0]
    assert v.matched_length == len(value)
    assert v.as_dict() == {
        "pattern_id": "bearer_token",
        "class": "bearer_token",
        "attr_key": "h",
        "matched_length": len(value),
    }
    # length only: no content substring of the secret is retained
    assert "a1" not in scrubbed["h"]


MULTI_SECRET_CASES = [
    "AKIAIOSFODNN7EXAMPLE and agent@example.com",
    "Authorization: Bearer c8f1e0d7aa4419be23 within prose",
]


@pytest.mark.parametrize("value", MULTI_SECRET_CASES, ids=["two-patterns", "pattern-in-prose"])
def test_embedded_matches_are_scrubbed_in_place(redactor: Redactor, value: str) -> None:
    scrubbed, violations = redactor.redact({"m": value})
    assert "[REDACTED:" in scrubbed["m"]
    assert "AKIA" not in scrubbed["m"]
    assert "@example.com" not in scrubbed["m"]
    assert len(violations) >= 1


# --------------------------------------------------------------------- allowlist
ALLOWLIST_CASES = [
    "oaa.metadata.run_note",
    "oaa.metadata.trace.receipt_hash",
    "oaa.metadata.tools.lease",
]


@pytest.mark.parametrize("key", ALLOWLIST_CASES, ids=["run_note", "hash", "lease"])
def test_allowlist_passthrough(redactor: Redactor, key: str) -> None:
    raw = "raw metadata payload with AKIAIOSFODNN7EXAMPLE inside"
    scrubbed, violations = redactor.redact({key: raw})
    assert scrubbed[key] == raw
    assert violations == []


def test_allowlist_glob_boundaries(redactor: Redactor) -> None:
    # exact key without a suffix is NOT covered by the `oaa.metadata.*` glob
    scrubbed, violations = redactor.redact({"oaa.metadata": "AKIAIOSFODNN7EXAMPLE"})
    assert "[REDACTED" in scrubbed["oaa.metadata"]
    assert violations
    # a sibling that does not start with `oaa.metadata.` stays governed too
    sibling = "oaa.metadata2"
    scrubbed2, violations2 = redactor.redact({sibling: "AKIAIOSFODNN7EXAMPLE"})
    assert "[REDACTED" in scrubbed2[sibling]
    assert all(v.attr_key == sibling for v in violations2)


# ------------------------------------------------------------ entropy heuristic
ENTROPY_BOUNDS = [
    # (case_id, value, expected_detected, why)
    (
        "digits-only-20",
        "01234567890123456789",
        False,
        "10-symbol alphabet: per-char entropy 3.32 < 4.0 threshold",
    ),
    (
        "single-char-blob",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        False,
        "entropy 0",
    ),
    (
        "prose-sentence",
        "the agent wrote a plain english sentence about tools",
        False,
        "prose: space chars excluded by charset gate, low entropy",
    ),
    (
        "kebab-run-id",
        "oaa-run-9f2a4b6c8d1e0f3a5b7c",
        False,
        "charset gate: dash-structured identifier",
    ),
    (
        "underscore-tag",
        "priv01_fixture_synthetic",
        False,
        "underscore tag: charset gate passes but entropy below threshold",
    ),
    (
        "hex-diverse-40",
        "3b8f1c0d7e2a5496b1f8c0d9e7a6b5c4",
        False,
        "mixed hex: per-char entropy 3.95 just below the 4.0 threshold (a full 16-symbol uniform string is exactly 4.0)",
    ),
    (
        "base64-url-hmac",
        "h0qXP4R9p2wQyv6N2sKgB8lMZcF7E3jU1aYt5rOiVw+=",
        True,
        "opaque base64ish blob: entropy 5.19 above threshold",
    ),
    (
        "digits-only-boundary-below-min-length",
        "0123456789012",
        False,
        "below min_length",
    ),
]


@pytest.mark.parametrize(
    ("case_id", "value", "expected_detected", "_why"),
    ENTROPY_BOUNDS,
    ids=[c[0] for c in ENTROPY_BOUNDS],
)
def test_entropy_bounds(
    redactor: Redactor, case_id: str, value: str, expected_detected: bool, _why: str
) -> None:
    scrubbed, violations = redactor.redact({"client.blob": value})
    if expected_detected:
        assert scrubbed["client.blob"].startswith("[REDACTED:high_entropy|")
        assert violations and violations[0].pattern_id == "entropy_heuristic"
    else:
        assert scrubbed["client.blob"] == value
        assert violations == []


def test_entropy_deterministic() -> None:
    a = shannon_entropy_per_char("0123456789abcdef0123")
    b = shannon_entropy_per_char("0123456789abcdef0123")
    assert a == b
    assert shannon_entropy_per_char("") == 0.0


def test_entropy_does_not_second_guess_pattern_hits(redactor: Redactor) -> None:
    # an email with enough entropy is classified by the PATTERN, not entropy
    _, violations = redactor.redact({"m": "ab12cd34ef56ab12cd34ef56@example.com"})
    assert [v.pattern_id for v in violations] == ["email"]


# ------------------------------------------------------------- config integrity
def test_config_version_and_hash(redactor: Redactor) -> None:
    cfg = redactor.config
    assert cfg.config_version == 1
    assert cfg.source_sha256 and len(cfg.source_sha256) == 64
    assert cfg.config_sha256 and len(cfg.config_sha256) == 64
    assert any("oaa.metadata.*" in g for g in cfg.allowlist)


# ------------------------------------------------------- seeded fixtures parity
def test_seeded_fixtures_match_the_patterns(redactor: Redactor, seeds: dict[str, dict]) -> None:
    for seed_id, seed in seeds.items():
        if seed["class"] == "allowlisted":
            continue
        key = seed["shape"].split("`")[1]
        scrubbed, violations = redactor.redact({key: seed["value"]})
        assert scrubbed[key].startswith("[REDACTED"), seed_id
        assert "len=" in scrubbed[key], seed_id
        assert violations, seed_id


def test_seeded_fixture_values_are_synthetic(seeds: dict[str, dict]) -> None:
    pems = [s["value"] for s in seeds.values() if s["class"] == "private_key_pem"]
    assert pems and pems[0].startswith("-----BEGIN RSA PRIVATE KEY-----")
    # regeneration is deterministic: re-running gen_seeds is a no-op (pinned RNG)
    out = (FIXTURES / "seeds" / "seeds.json").read_text(encoding="utf-8")
    assert json.loads(out)["purpose"].startswith("PRIV-01")


# ------------------------------------------------------------ collector scan
def _raw_leaky_maps(seeds: dict[str, dict]) -> list[dict]:
    s = {sid: sv["value"] for sid, sv in seeds.items()}
    return [
        {
            "aws.access_key": s["seed-aws-access-key"],
            "aws.secret": s["seed-aws-secret"],
            "http.request.header.authorization": s["seed-bearer-token"],
            "oidc.token": s["seed-jwt"],
            "tls.client_key_pem": s["seed-private-key-pem"],
            "user.email": s["seed-email"],
            "llm.input_messages": "api_key=" + s["seed-aws-secret"][:16],
            "client.hmac_key": s["seed-high-entropy"],
            "oaa.run_id": "oaa-run-abc123",
            "oaa.content_class": "priv01_fixture_synthetic",
        }
    ]


def test_collector_scan_counts_and_never_echoes(redactor: Redactor, seeds: dict[str, dict]) -> None:
    report = scan_batch(_raw_leaky_maps(seeds), redactor)
    assert report.span_count == 1
    assert not report.clean
    assert report.violation_count >= 8  # one or more per seeded class
    assert set(report.count_by_class()) <= {
        "aws_access_key",
        "bearer_token",
        "jwt",
        "private_key_pem",
        "email",
        "credential_kv",
        "high_entropy",
    }
    # never echo: report serialisation must not contain any seed value
    dumped = json.dumps(report.as_dict())
    for seed in seeds.values():
        assert seed["value"] not in dumped, seed["id"]
    dumped_violations = json.dumps([v.as_dict() for v in report.violations])
    assert "AKIA" not in dumped_violations
    assert all("value" not in json.dumps(v.as_dict()).lower() for v in report.violations)


def test_collector_scan_clean_payload(redactor: Redactor, seeds: dict[str, dict]) -> None:
    good = [
        {
            "oaa.run_id": "oaa-run-abc123",
            "oaa.content_class": "synthetic_public",
            "oaa.metadata.note": "anything goes here, AKIAIOSFODNN7EXAMPLE",
        },
    ]
    report = scan_batch(good, redactor)
    assert report.clean and report.violation_count == 0 and report.span_count == 1


def test_collector_scan_is_idempotent_over_redacted_batches(
    redactor: Redactor, seeds: dict[str, dict]
) -> None:
    scrubbed, _ = redactor.redact(_raw_leaky_maps(seeds)[0])
    report = scan_batch([scrubbed], redactor)
    assert report.clean, [v.as_dict() for v in report.violations]


def test_collector_quarantine_selection(redactor: Redactor, seeds: dict[str, dict]) -> None:
    maps = [
        *_raw_leaky_maps(seeds),
        {"oaa.run_id": "oaa-clean-1", "oaa.content_class": "synthetic_public"},
    ]
    ids = ["span-raw", "span-clean"]
    report = scan_batch(maps, redactor)
    held = quarantine(ids, maps, report)
    assert held == ["span-raw"]
    assert sorted(held) == held  # deterministic ordering


def test_scan_report_shape() -> None:
    report = ScanReport(span_count=3)
    assert report.clean
    assert len(report.violations) == 0
    assert report.as_dict() == {
        "span_count": 3,
        "violation_count": 0,
        "counts_by_class": {},
        "clean": True,
    }


# ---------------------------------------------------------- redaction core API
def test_redaction_does_not_mutate_input(redactor: Redactor) -> None:
    raw = {"k": "AKIAIOSFODNN7EXAMPLE"}
    redactor.redact(raw)
    assert raw["k"] == "AKIAIOSFODNN7EXAMPLE"


def test_non_string_attributes_pass_through(redactor: Redactor) -> None:
    raw = {"oaa.stub": True, "count": 3, "none_val": None}
    scrubbed, violations = redactor.redact(raw)
    assert scrubbed == raw and violations == []


# ------------------------------------------------- OTel wrapper (needs otel sdk)
def test_otlp_wrappers_export_and_count() -> None:
    pytest.importorskip("opentelemetry.sdk.trace", reason="opentelemetry-sdk not installed")
    from oaa_instrumentation.otel_processor import (
        QuarantiningSpanExporter,
        RedactingSpanExporter,
        span_attribute_map,
    )
    from opentelemetry.sdk.trace import Tracer, TracerProvider  # noqa: F401
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    seeds = json.loads((FIXTURES / "seeds" / "seeds.json").read_text(encoding="utf-8"))["seeds"]
    value = next(s["value"] for s in seeds if s["id"] == "seed-aws-access-key")

    memory = InMemorySpanExporter()
    provider = TracerProvider()
    # protected chain: redaction -> quarantine scan -> memory
    quarantine_layer = QuarantiningSpanExporter(memory, Redactor.from_yaml())
    sink = RedactingSpanExporter(quarantine_layer, Redactor.from_yaml())
    provider.add_span_processor(_ExportOnEnd(sink))
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span(
        "op", attributes={"aws.access_key": value, "oaa.run_id": "oaa-run-1"}
    ):
        pass
    provider.shutdown()
    exported = memory.get_finished_spans()
    assert len(exported) == 1
    scrubbed = span_attribute_map(exported[0])
    assert scrubbed["aws.access_key"].startswith("[REDACTED:aws_access_key")
    assert value not in json.dumps(scrubbed)
    assert quarantine_layer.summary()["violation_count"] == 0
    assert quarantine_layer.summary()["clean"] is True


class _ExportOnEnd:
    """Minimal synchronously-exporting span processor for wrapper tests."""

    def __init__(self, exporter):
        self.exporter = exporter

    def on_start(self, span, parent_context):  # pragma: no cover
        return None

    def on_end(self, span) -> None:
        self.exporter.export((span,))

    def _on_ending(self, span) -> None:  # pragma: no cover - SDK hook
        return None

    def shutdown(self) -> None:  # pragma: no cover
        return None

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return True


def test_quarantine_layer_holds_back_violations() -> None:
    pytest.importorskip("opentelemetry.sdk.trace", reason="opentelemetry-sdk not installed")
    from oaa_instrumentation.otel_processor import QuarantiningSpanExporter
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

    seeds = json.loads((FIXTURES / "seeds" / "seeds.json").read_text(encoding="utf-8"))["seeds"]
    hmac_seed = next(s["value"] for s in seeds if s["id"] == "seed-high-entropy")

    memory = InMemorySpanExporter()
    provider = TracerProvider()
    layer = QuarantiningSpanExporter(memory, Redactor.from_yaml())
    provider.add_span_processor(_ExportOnEnd(layer))
    tracer = provider.get_tracer("test")
    with tracer.start_as_current_span("bad", attributes={"client.hmac_key": hmac_seed}):
        pass
    provider.shutdown()
    assert len(memory.get_finished_spans()) == 0  # held back entirely
    summary = layer.summary()
    assert summary["violation_count"] == 1
    assert summary["quarantined_span_count"] == 1
    # secret never surfaced by the audit trail
    assert hmac_seed not in json.dumps(summary)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(pytest.main([__file__]))
