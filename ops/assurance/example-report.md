# Open Agent Assurance — scoped assurance report (GOV-01)

Generated: 2026-11-04T12:00:00+00:00

Source store: `services/investigation-ui/demo_data` (read-only; canonical evidence bytes were never read verbatim into this report — index plane only).

One report per slice; this document supersedes no other assurance document and is itself not evidence.

## Evidence verification states (ADR-0001)

### Verification state distribution

| state | count |
| --- | --- |
| `valid` | 5 |
| `invalid` | 0 |
| `unknown_key` | 1 |
| `unsupported_schema` | 1 |
| `pending` | 1 |
| `unavailable` | 1 |
| `not_applicable` | 1 |

> Explicit unknown states (`unknown_key`, `unsupported_schema`, `pending`, `unavailable`) are reported in their own buckets and never silently omitted — fail-visible by construction (ADR-0001).

## Correlation state distribution (ADR-0002)

### Correlation state distribution

| state | count |
| --- | --- |
| `matched` | 4 |
| `receipt_missing` | 1 |
| `trace_missing` | 0 |
| `ambiguous` | 2 |
| `late_arrival` | 1 |
| `duplicate` | 1 |

## Findings (retained, never dropped)

Active findings: 1

| rule | severity | confidence | subject | explanation |
| --- | --- | --- | --- | --- |
| `SEC-002` | medium | high | — | receipt verification state 'unsupported_schema' (definitive failure, ADR-0001) |

### Suppressed findings (retained with reasons): 1

| rule | severity | suppression reason | explanation |
| --- | --- | --- | --- |
| `SEC-001` | high | documented maintenance-window coverage gap on t-sim-sup trace (CHANGELOG 2026-11-04) | gate receipt missing after grace for privileged tool 'shell' on trace 't-sim-sup-0000000000000000000000000000aa' |

## Tool-side reconciliation summary

Tool-side audit events: **not provided — coverage unverified**. The receipt-side index alone cannot establish what executed on the tool side; this is an explicit limit of the current report scope.

## Summary counts

- Receipts indexed: 10
- Verified states in the explicit unknown buckets: 4
- Traces with terminal correlation records: 9
- Open (in-grace) correlation records: 0
- Active findings: 1; suppressed-but-retained findings: 1
- Tool-side audit events: not provided — coverage unverified

## Unknowns and unverifiable ranges

- Verification: 4 of 10 indexed receipts are in an explicit unknown state (`unknown_key`, `unsupported_schema`, `pending`, `unavailable`) — no integrity or authority claim is made for them.
- Correlation: `receipt_missing` records lack a corroborating receipt entirely (1 traces); 0 correlation record(s) are open inside the grace window and are not results.
- Unverifiable ranges: any trace with no span carrying a gate receipt, and any verification state of `unavailable` (verifier could not run at ingest time), are ranges this report cannot verify.
- Receipts outside the ingested evidence store (unsampled sinks, prior retention windows already deleted per the records lifecycle) are unverifiable by construction.

## Mandatory limits (fixed section — do not edit)

### Scope

- This report covers the gated paths only: tool invocations that pass the receipt-based gate and appear in the ingested evidence store for the queried range. Ungated paths (non-tool model turns, producer-side traffic before the gate, external systems) are out of scope and out of evidence.

### Coverage per tool (custody coverage map, default `unverified`)

| tool | coverage |
| --- | --- |
| `file_write` | gate |
| `http_fetch` | gate |
| `read_file` | unverified |
| `shell` | gate |
| `write_file` | unverified |

### Verification trust model

In one line: verification asserts **integrity and authority within trust policy version `evd-trust-1`** — and never safety, appropriateness, or compliance (ADR-0001: a `valid` result says the bytes match the signing key trusted at event time, nothing further).

### No legal or regulatory statement

A receipt or this report does not establish legal or regulatory compliance of any kind. It records what was cryptographically observed inside a deliberately narrow scope and no more.

### Unknowns and unverifiable ranges

See the *Unknowns and unverifiable ranges* section above — repeated here by reference; the limits section is void without it.
