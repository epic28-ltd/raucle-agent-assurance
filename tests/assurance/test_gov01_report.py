# SPDX-License-Identifier: Apache-2.0
"""GOV-01 scoped assurance report generator tests.

Fixture stores are the UI demo data (read-only) plus a tmp store derived
from it with a mixed-state verification index (every ADR-0001 state at
least once, including `invalid`) and an extra documented suppression.

The no-claim guarantee is enforced structurally: the generated report
must not contain any banned compliance-claim term, and the mandatory
limits section must be present. Determinism is asserted with a pinned
injected clock.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import shutil

import pytest
from ops.assurance.generate_report import (
    BANNED_CLAIM_STEMS,
    COVERAGE_CONFIG_PATH,
    TRUST_POLICY_VERSION,
    assert_no_compliance_claims,
    generate_report,
    load_coverage,
    load_tool_audit,
)

DEMO = pathlib.Path(__file__).resolve().parents[2] / "services" / "investigation-ui" / "demo_data"
CLOCK = dt.datetime(2026, 11, 5, 12, 0, 0, tzinfo=dt.UTC)


def _mixed_store(tmp_path: pathlib.Path) -> pathlib.Path:
    """Copy the demo store and force every verification state + suppression."""
    dest = tmp_path / "mixed-store"
    shutil.copytree(DEMO, dest)
    # verification index: keep only one valid row, then add every state at
    # least once (invalid included — the demo store has zero of those).
    lines = (dest / "verification_index.jsonl").read_text().splitlines()
    header = [ln for ln in lines if ln.startswith("#")]
    rows = [ln for ln in lines if ln and not ln.startswith("#")]
    first = json.loads(rows[0])
    keep = {first["receipt_hash"]: first}
    for st in (
        "invalid",
        "unknown_key",
        "unsupported_schema",
        "pending",
        "unavailable",
        "not_applicable",
    ):
        fake = dict(first)
        fake["receipt_hash"] = (
            f"sha256:gov01{st[:6]}0000000000000000000000000000000000000000000000000000"
        )
        fake["status"] = st
        fake["detail"] = f"GOV-01 mixed-state fixture row ({st})"
        keep[fake["receipt_hash"]] = fake
    (dest / "verification_index.jsonl").write_text(
        "\n".join(header + [json.dumps(r) for r in keep.values()]) + "\n"
    )
    # extra documented suppression so the fixture exercises retention.
    fixture = json.loads((dest / "rules_fixture.json").read_text())
    fixture["suppressions"].append(
        {
            "rule_id": "SEC-002",
            "reason": "GOV-01 fixture: unsupported_schema row pre-dates trust-policy v1 rollout",
            "subject": None,
        }
    )
    (dest / "rules_fixture.json").write_text(json.dumps(fixture))
    return dest


@pytest.fixture(scope="module")
def mixed_report(tmp_path_factory: pytest.TempPathFactory) -> str:
    tmp = tmp_path_factory.mktemp("gov01")
    return generate_report(_mixed_store(tmp), clock=CLOCK)


@pytest.fixture(scope="module")
def demo_report() -> str:
    return generate_report(DEMO, clock=CLOCK)


def test_every_verification_state_bucket_present(mixed_report: str) -> None:
    for st in (
        "valid",
        "invalid",
        "unknown_key",
        "unsupported_schema",
        "pending",
        "unavailable",
        "not_applicable",
    ):
        assert f"| `{st}` |" in mixed_report, st
    # invalid must be non-zero in the mixed fixture
    row = next(ln for ln in mixed_report.splitlines() if ln.startswith("| `invalid` |"))
    assert int(row.split("|")[2].strip()) >= 1


def test_every_verification_state_bucket_present_demo(demo_report: str) -> None:
    for st in ("invalid", "unavailable", "unknown_key"):
        assert f"| `{st}` |" in demo_report


def test_correlation_states_present(demo_report: str) -> None:
    for st in (
        "matched",
        "receipt_missing",
        "trace_missing",
        "ambiguous",
        "late_arrival",
        "duplicate",
        "pending",
    ):
        assert f"| `{st}` |" in demo_report, st


def test_limits_section_present(mixed_report: str) -> None:
    assert "## Mandatory limits (fixed section" in mixed_report
    for needle in (
        "gated paths only",
        "coverage map",
        "unverified",
        "integrity and authority",
        f"`{TRUST_POLICY_VERSION}",
        "does not establish legal or regulatory",
        "Unknowns and unverifiable ranges",
    ):
        assert needle in mixed_report, needle


def test_no_banned_claim_terms(mixed_report: str, demo_report: str) -> None:
    # The generator self-guards; the test re-scans independently.
    for report in (mixed_report, demo_report):
        assert_no_compliance_claims(report)  # raises on a positive-context claim
        low = report.lower()
        assert "does not establish legal or regulatory" in low  # disclaimer present
        for stem in BANNED_CLAIM_STEMS:  # every occurrence, if any, is negated-only
            for ln in low.splitlines():
                if stem in ln:
                    assert_no_compliance_claims(ln)


def test_scanner_rejects_positive_claims() -> None:
    for bad in (
        "the agent run is compliant with policy 3",
        "this report certifies the evidence chain",
        "receipts were approved by the security team",
    ):
        with pytest.raises(ValueError):
            assert_no_compliance_claims(bad)
    for good in (
        "this report does not certify anything",
        "a receipt does not establish compliance",
    ):
        assert_no_compliance_claims(good)


def test_suppressed_findings_shown_with_reasons(mixed_report: str) -> None:
    assert "Suppressed findings (retained with reasons): " in mixed_report
    assert (
        "GOV-01 fixture: unsupported_schema row pre-dates trust-policy v1 rollout" in mixed_report
    )
    assert "documented maintenance-window coverage gap" in mixed_report
    # a suppressed finding also appears in an active-findings position? no: suppressed
    # ones are listed only under the retained-suppressed table.
    sec001_line = next(ln for ln in mixed_report.splitlines() if ln.startswith("| `SEC-001`"))
    assert "maintenance-window" in sec001_line


def test_audit_events_reconciliation(tmp_path: pathlib.Path) -> None:
    audit = tmp_path / "tool_audit.jsonl"
    rows = [
        {"tool": "shell", "outcome": "success", "ref": "a-1"},
        {"tool": "shell", "outcome": "failure", "ref": "a-2"},
        {"tool": "http_fetch", "outcome": "success", "ref": "a-3"},
    ]
    audit.write_text("# rows\n" + "\n".join(json.dumps(r) for r in rows) + "\n")
    assert len(load_tool_audit(audit)) == 3
    report = generate_report(DEMO, clock=CLOCK, audit_events_path=audit)
    assert "Tool-side audit records: **3**" in report
    # without events the section must be explicit:
    none_report = generate_report(DEMO, clock=CLOCK)
    assert "not provided — coverage unverified" in none_report


def test_deterministic_with_pinned_clock(tmp_path: pathlib.Path) -> None:
    store = _mixed_store(tmp_path)
    a = generate_report(store, clock=CLOCK)
    b = generate_report(store, clock=CLOCK)
    assert a == b


def test_coverage_map_defaults_unverified(mixed_report: str) -> None:
    cov = load_coverage(COVERAGE_CONFIG_PATH)
    listed = {
        ln.split("`")[1]
        for ln in mixed_report.splitlines()
        if (ln.startswith("| `") and "gate" in ln) or ln.startswith("| `")
    }
    for tool in listed:
        assert cov.get(tool, "unverified") == (
            "gate" if f"| `{tool}` | gate |" in mixed_report else "unverified"
        )
