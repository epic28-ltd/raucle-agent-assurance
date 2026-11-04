# oaa-audit-sources (K2 audit reconciliation connectors)

<!-- SPDX-License-Identifier: Apache-2.0 -->

Pure, offline connectors for reconciling gate receipts (vantage G, ADR-0002)
against tool-side audit records (vantage A, ADR-0004):

- `src/oaa_audit_sources/normalize.py` — normalizers per source producing v1
  `AuditCandidate` records:
  `{source, source_event_id, event_time (UTC ISO), actor, action, resource,
  session_binding, unverified_linkage, raw_ref, synthetic}`.
  Sources: `aws_cloudtrail` (CloudTrail management events, e.g. CloudTrail
  Lake export rows) and `github_audit` (GitHub audit log events).
- `src/oaa_audit_sources/reconcile.py` — `reconcile(candidates,
  receipt_index_rows, conventions)` with ADR-0002 correlation semantics and
  ADR-0004 bypass states (see `docs/spikes/K2-findings.md` for the full table
  and the two binding conventions).

## No network. Ever.

**This library performs NO network calls: there is no HTTP, DNS or I/O of any
kind in `src/`.** Normalizers take already-exported JSON lists; the caller is
the export surface (CloudTrail Lake query results, GitHub audit-log export).
Collectors/fetchers (S3/Lake queries, GH audit API pagination, MCP gateway
connector) are **deployment glue, deliberately out of scope for this
library** and documented as future work in `docs/spikes/K2-findings.md` —
they belong to the companion's ingest layer, where ADR-0001's trust model
applies (collectors run in a vantage point the agent does not control).

## Payload discipline

`AuditCandidate.raw_ref` is restricted to the keys named in
`AuditSourceConfig.declared_raw_fields` (the deployment's declared passthrough
contract). Fields outside the declaration — notably CloudTrail
`requestParameters` and its payload-bearing cousins, and GitHub's internal
`request_id` — are dropped at normalize time. GitHub `request_id` is
recorded only as `unverified_linkage` text and is never eligible for
correlation (GitHub has no client-supplied correlation field).