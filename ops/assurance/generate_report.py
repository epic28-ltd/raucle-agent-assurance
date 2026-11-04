# SPDX-License-Identifier: Apache-2.0
"""Open Agent Assurance — GOV-01 scoped assurance report generator.

Produces ONE markdown report from demo-data-style inputs (the same
read-only store layout as services/investigation-ui/demo_data):

- evidence verification counts per ADR-0001 state (explicit unknown /
  invalid / unavailable buckets included, zero counts shown);
- correlation state distribution per ADR-0002 (plus open/pending);
- findings from the RULE-01 rules engine output, with suppressed
  findings RETAINED and their documented reasons shown;
- tool-side reconciliation summary when tool-side audit events are
  provided (``kind: tool_audit`` JSONL rows); otherwise the section
  states ``not provided - coverage unverified``;
- a FIXED MANDATORY LIMITS section (scope, per-tool coverage from
  ``ops/assurance/config/coverage.yaml`` with an ``unverified`` default,
  one-line verification trust model, and the explicit statement that a
  receipt or this report does not establish legal or regulatory
  compliance);

The report NEVER makes a compliance claim — a test scans the generated
output for banned claim terms.

The generation clock is injectable (``--clock``) so output is
byte-deterministic across runs (verified by a test).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
for _src in (
    REPO_ROOT / "packages" / "raucle-adapter" / "src",
    REPO_ROOT / "services" / "correlation" / "src",
    REPO_ROOT / "services" / "rules" / "src",
    REPO_ROOT / "services" / "investigation-ui" / "src",
):
    if _src.is_dir() and str(_src) not in sys.path:
        sys.path.insert(0, str(_src))

from oaa_investigation_ui.data import UNKNOWN_STATES, VERIFICATION_STATES, DemoData  # noqa: E402

from oaa_raucle_adapter.evidence_plane import TRUST_POLICY_VERSION  # noqa: E402

CORRELATION_STATES = (
    "matched",
    "receipt_missing",
    "trace_missing",
    "ambiguous",
    "late_arrival",
    "duplicate",
)
COVERAGE_CONFIG_PATH = pathlib.Path(__file__).resolve().parent / "config" / "coverage.yaml"

REPORT_TITLE = "Open Agent Assurance — scoped assurance report (GOV-01)"

# Banned claim stems: any report line asserting one of these as a claim is a
# violation. A stem inside an explicit NEGATION (e.g. "does not establish
# ... compliance") is the required disclaimer, not a claim.
BANNED_CLAIM_STEMS = ("complian", "certif", "approv", "accredit", "attest", "warrant")
_NEGATORS = ("not ", "no ", "never ", "without ", "nor ", " n't", "non-")


def assert_no_compliance_claims(text: str) -> None:
    """Structural no-claim guard: banned stems may appear only in negated
    (disclaimer) contexts. Raises ValueError naming the offending line."""
    for raw_line in text.splitlines():
        line = raw_line.lower()
        for stem in BANNED_CLAIM_STEMS:
            start = line.find(stem)
            while start != -1:
                window = line[max(0, start - 60) : start]
                if not any(neg in window for neg in _NEGATORS):
                    raise ValueError(
                        f"banned claim term {stem!r} in positive context: {raw_line!r}"
                    )
                start = line.find(stem, start + 1)


# ------------------------------------------------------------ inputs -------


def load_coverage(path: pathlib.Path = COVERAGE_CONFIG_PATH) -> dict[str, str]:
    """Load the tool-side coverage map; unlisted tools are ``unverified``."""
    import yaml  # noqa: PLC0415 — config-loading convenience only

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if int(raw.get("version", 0)) != 1:
        raise ValueError(f"unsupported coverage.yaml version: {raw.get('version')!r}")
    return {
        str(k): str(v.get("coverage", "unverified")) for k, v in (raw.get("tools") or {}).items()
    }


def load_tool_audit(path: pathlib.Path) -> list[dict]:
    """Load tool-side audit index rows (JSONL, ``#`` comments allowed)."""
    rows: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        rows.append(json.loads(line))
    return rows


# ----------------------------------------------------------- sections ------


def _counts_table(label: str, states: tuple[str, ...], counts: dict[str, int]) -> list[str]:
    out = [f"### {label}", "", "| state | count |", "| --- | --- |"]
    for st in states:
        out.append(f"| `{st}` | {counts.get(st, 0)} |")
    out.append("")
    return out


def _verification_counts(data: DemoData) -> dict[str, int]:
    counts = {s: 0 for s in VERIFICATION_STATES}
    for row in data._verif.values():
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    return counts


def _correlation_counts(data: DemoData) -> tuple[dict[str, int], int]:
    counts = {s: 0 for s in CORRELATION_STATES}
    seen: set[str] = set()
    for payload in data.correlation_by_trace.values():
        if payload["trace_id"] in seen:
            continue
        seen.add(payload["trace_id"])
        if payload["state"] in counts:
            counts[payload["state"]] += 1
    return counts, data.pending_count


def _findings_section(data: DemoData) -> list[str]:
    active = [f for f in data.findings if not f["suppressed"]]
    suppressed = [f for f in data.findings if f["suppressed"]]
    out = ["## Findings (retained, never dropped)", ""]
    out.append(f"Active findings: {len(active)}\n")
    if active:
        out += [
            "| rule | severity | confidence | subject | explanation |",
            "| --- | --- | --- | --- | --- |",
        ]
        for f in active:
            out.append(
                f"| `{f['rule_id']}` | {f['severity']} | {f['confidence']} "
                f"| {f['subject'] or '—'} | {f['explanation']} |"
            )
        out.append("")
    else:
        out.append("No active findings in the covered scope. Absence of findings is not a ")
        out.append("statement about paths outside the scope (see mandatory limits).\n")
    out.append(f"### Suppressed findings (retained with reasons): {len(suppressed)}\n")
    if suppressed:
        out += [
            "| rule | severity | suppression reason | explanation |",
            "| --- | --- | --- | --- |",
        ]
        for f in suppressed:
            out.append(
                f"| `{f['rule_id']}` | {f['severity']} | {f['suppression_reason']} | {f['explanation']} |"
            )
        out.append("")
    else:
        out.append("_None — no finding was suppressed for this slice._\n")
    return out


def _reconciliation_section(rows: list[dict] | None) -> list[str]:
    out = ["## Tool-side reconciliation summary", ""]
    if not rows:
        out.append(
            "Tool-side audit events: **not provided — coverage unverified**. "
            "The receipt-side index alone cannot establish what executed on the tool side; "
            "this is an explicit limit of the current report scope.\n"
        )
        return out
    total = len(rows)
    by_tool: dict[str, int] = {}
    for r in rows:
        by_tool[r.get("tool") or "unknown"] = by_tool.get(r.get("tool") or "unknown", 0) + 1
    out.append(f"Tool-side audit records: **{total}** (from the provided audit event file).\n")
    out += ["| tool | audit records |", "| --- | --- |"]
    for tool in sorted(by_tool):
        out.append(f"| `{tool}` | {by_tool[tool]} |")
    out.append("")
    out.append(
        "Reconciliation against the receipt-side index must be treated as incomplete: "
        "only records that both sides observed can be reconciled, and unmatched records "
        "on either side are coverage gaps, not results.\n"
    )
    return out


def _unknowns_section(data: DemoData) -> list[str]:
    verif = _verification_counts(data)
    corr, pending_corr = _correlation_counts(data)
    out = ["## Unknowns and unverifiable ranges", ""]
    total_v = sum(verif.values())
    unk_v = sum(verif.get(s, 0) for s in UNKNOWN_STATES)
    out.append(
        f"- Verification: {unk_v} of {total_v} indexed receipts are in an explicit unknown "
        "state (`" + "`, `".join(s for s in VERIFICATION_STATES if s in UNKNOWN_STATES) + "`) — "
        "no integrity or authority claim is made for them."
    )
    out.append(
        f"- Correlation: `receipt_missing` records lack a corroborating receipt entirely "
        f"({corr.get('receipt_missing', 0)} traces); {pending_corr} correlation record(s) are "
        "open inside the grace window and are not results."
    )
    out.append(
        "- Unverifiable ranges: any trace with no span carrying a gate receipt, and any "
        "verification state of `unavailable` (verifier could not run at ingest time), are "
        "ranges this report cannot verify."
    )
    out.append(
        "- Receipts outside the ingested evidence store (unsampled sinks, prior retention "
        "windows already deleted per the records lifecycle) are unverifiable by construction."
    )
    out.append("")
    return out


def _limits_section(data: DemoData, coverage: dict[str, str]) -> list[str]:
    tools: set[str] = set(coverage)
    for meta in data._receipt_meta.values():
        if meta.get("tool"):
            tools.add(meta["tool"])
    out = ["## Mandatory limits (fixed section — do not edit)", ""]
    out.append("### Scope")
    out.append("")
    out.append(
        "- This report covers the gated paths only: tool invocations that pass the "
        "receipt-based gate and appear in the ingested evidence store for the queried "
        "range. Ungated paths (non-tool model turns, producer-side traffic before the "
        "gate, external systems) are out of scope and out of evidence."
    )
    out.append("")
    out.append("### Coverage per tool (custody coverage map, default `unverified`)")
    out.append("")
    out += ["| tool | coverage |", "| --- | --- |"]
    for tool in sorted(tools):
        out.append(f"| `{tool}` | {coverage.get(tool, 'unverified')} |")
    out.append("")
    out.append("### Verification trust model")
    out.append("")
    out.append(
        f"In one line: verification asserts **integrity and authority within trust policy "
        f"version `{TRUST_POLICY_VERSION}`** — and never safety, appropriateness, or "
        f"compliance (ADR-0001: a `valid` result says the bytes match the signing key "
        f"trusted at event time, nothing further)."
    )
    out.append("")
    out.append("### No legal or regulatory statement")
    out.append("")
    out.append(
        "A receipt or this report does not establish legal or regulatory "
        "compliance of any kind. It records what was cryptographically observed "
        "inside a deliberately narrow scope and no more."
    )
    out.append("")
    out.append("### Unknowns and unverifiable ranges")
    out.append("")
    out.append(
        "See the *Unknowns and unverifiable ranges* section above — repeated here by reference; the limits section is void without it."
    )
    out.append("")
    return out


# ---------------------------------------------------------- generation -----


def generate_report(
    data_dir: pathlib.Path,
    *,
    clock: dt.datetime | None = None,
    coverage_path: pathlib.Path = COVERAGE_CONFIG_PATH,
    audit_events_path: pathlib.Path | None = None,
) -> str:
    """Return the markdown report text. Deterministic for a fixed clock."""
    data = DemoData(pathlib.Path(data_dir))
    coverage = load_coverage(coverage_path)
    rows = load_tool_audit(audit_events_path) if audit_events_path is not None else None
    clock = clock or dt.datetime.now(dt.UTC)
    verif = _verification_counts(data)
    corr, pending_corr = _correlation_counts(data)
    active = [f for f in data.findings if not f["suppressed"]]
    suppressed = [f for f in data.findings if f["suppressed"]]

    lines: list[str] = [f"# {REPORT_TITLE}", ""]
    lines += [
        f"Generated: {clock.isoformat()}",
        "",
        f"Source store: `{data.dir}` (read-only; canonical evidence bytes were never read verbatim into this report — index plane only).",
        "",
        "One report per slice; this document supersedes no other assurance document and is itself not evidence.",
        "",
    ]
    lines += ["## Evidence verification states (ADR-0001)", ""]
    lines += _counts_table("Verification state distribution", VERIFICATION_STATES, verif)
    lines += [
        "> Explicit unknown states (`unknown_key`, `unsupported_schema`, `pending`, "
        "`unavailable`) are reported in their own buckets and never silently omitted — "
        "fail-visible by construction (ADR-0001).",
        "",
    ]
    lines += ["## Correlation state distribution (ADR-0002)", ""]
    lines += _counts_table(
        "Correlation state distribution", CORRELATION_STATES, {**corr, "pending": pending_corr}
    )
    lines += _findings_section(data)
    lines += _reconciliation_section(rows)
    lines += ["## Summary counts", ""]
    lines += [
        f"- Receipts indexed: {sum(verif.values())}",
        f"- Verified states in the explicit unknown buckets: {sum(verif.get(s, 0) for s in UNKNOWN_STATES)}",
        f"- Traces with terminal correlation records: {sum(corr.values())}",
        f"- Open (in-grace) correlation records: {pending_corr}",
        f"- Active findings: {len(active)}; suppressed-but-retained findings: {len(suppressed)}",
        "- Tool-side audit events: "
        + (
            f"{len(rows)} records (reconciliation summary above)"
            if rows
            else "not provided — coverage unverified"
        ),
        "",
    ]
    lines += _unknowns_section(data)
    lines += _limits_section(data, coverage)
    text = "\n".join(lines).rstrip() + "\n"
    assert_no_compliance_claims(text)  # self-guard: never emit a claim
    return text


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=REPORT_TITLE)
    ap.add_argument("--data-dir", required=True, help="demo-data-style evidence/index directory")
    ap.add_argument("--out", required=True, help="output markdown path")
    ap.add_argument("--clock", help="injected generation clock, ISO-8601 (pins determinism)")
    ap.add_argument("--audit-events", help="optional tool_audit JSONL file for reconciliation")
    args = ap.parse_args(argv)
    clock = dt.datetime.fromisoformat(args.clock).astimezone(dt.UTC) if args.clock else None
    report = generate_report(
        pathlib.Path(args.data_dir),
        clock=clock,
        audit_events_path=pathlib.Path(args.audit_events) if args.audit_events else None,
    )
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(report, encoding="utf-8")
    print(f"wrote {out} ({len(report)} chars)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
