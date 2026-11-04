# K2 — Audit Reconciliation Connectors: Findings (EPIC M)

<!-- SPDX-License-Identifier: Apache-2.0 -->

Local-only spike, nothing external contacted. Code:
`integrations/audit-sources/` (Apache-2.0), pytest in
`integrations/audit-sources/tests/`. Build: pure Python ≥3.11, **no
dependencies, no I/O of any kind in `src/`** — normalizers consume
already-exported JSON; collectors/fetchers are deployment glue (see "What
remains").

## Design

- **Normalizer layer (`normalize.py`).** One normalizer per source, each a
  pure function `(list[dict], AuditSourceConfig) -> list[AuditCandidate]`.
  The v1 candidate record is:
  `{source, source_event_id, event_time (UTC ISO-8601, 'Z'),
  actor, action (normalized tool/op), resource, session_binding,
  unverified_linkage, raw_ref, synthetic}`. `synthetic` is an explicit
  marker for hand-built test records — mirrors `ReceiptRecord.synthetic` in
  oaa-correlation (synthetic rows are never real evidence).
- **Payload discipline.** `raw_ref` accepts ONLY keys named in
  `AuditSourceConfig.declared_raw_fields` (presence-checked; no invented
  keys). Undeclared fields — CloudTrail `requestParameters`/
  `responseElements`/`userAgent`, GitHub `request_id`/`user_agent` — are
  dropped at normalize time, not filtered downstream.
- **Reconciler (`reconcile.py`).** `reconcile(candidates, receipt_index_rows,
  conventions, at=None) -> ReconciliationResult`. Same philosophy as
  `oaa_correlation.core.reconcile` (ADR-0002): explicit reconciliation
  instant, grace window, `pending` for in-grace records (absence is an open
  question, never silently graded), duplicate deliveries collapse to one
  logical record with provenance preserved.
- **Two matching phases, strong before weak.** Phase 1: binding-token
  equality (exclusive, high confidence). Phase 2, only without a binding:
  time-window + actor agreement → `matched_degraded` (medium confidence,
  notes flag it). Phase 3, nothing matched: privileged op per the
  registry config → `bypass_suspected`; unprivileged → `receipt_missing`.
  Unclaimed receipts → `receipt_only_gap` (ADR-0004 evidence_gap: **NOT
  proof of non-execution**). Multiple distinct receipts on one candidate →
  `ambiguous` (never silently resolved).

## Field mapping tables

### AWS CloudTrail (management events, e.g. CloudTrail Lake export)

Research-validated shape: `userIdentity.principalId` carries the session
name as the suffix after `:` (AssumedRole), `sessionContext.sourceIdentity`
carries the identity provider-set actor, mgmt fields
`eventName, eventSource, eventTime, userIdentity, requestParameters,
resources, eventID, recipientAccountId, awsRegion`. Retention: management
events 90 days by default; CloudTrail Lake up to 7–10 years.

| Audit field | Candidate field | Notes |
|---|---|---|
| `eventID` | `source_event_id` | required; un-IDed events are rejected (nothing to reference) |
| `eventTime` | `event_time` | normalized to UTC ISO with `Z` |
| `userIdentity.sessionContext.sourceIdentity` | `actor` | preferred actor |
| `userIdentity.userName` / `principalId` prefix | `actor` | fallbacks |
| principalId session suffix (= roleSessionName) | `session_binding` | the gate-set `oaa-<receipt_hash_prefix>` token; sourceIdentity is the binding fallback when no session name exists |
| `eventName` + `eventSource` | `action` | `CLOUDTRAIL_OP_MAP` for known events (e.g. `GetObject`→`s3.get_object`, `InvokeFunction`→`lambda.invoke`), else `service.snake_case(eventName)`; config `op_map` overrides |
| `resources[].resourceType/Name` | `resource` | `type/name`; None when absent |
| `eventSource`, `recipientAccountId`, `awsRegion` | `raw_ref` | default declared, payload-free passthrough |

### GitHub audit log (exported events)

Research-validated shape: `actor`, `repo`, `action`, `@timestamp` /
`created_at`, `actor_is_bot` / `actor_is_agent` flags, `hashed_token`,
`token_scopes`, `programmatic_access_type`, `integration`,
`application_client_id`. `request_id` is **GitHub-internal**: we cannot
verify what it refers to, it is excluded from correlation use and recorded
only as `unverified_linkage` text. There is NO client-supplied correlation
field on GitHub audit events. Retention: audit log events retained
indefinitely on paid plans (retention window is org/billable-user count
dependent); the export is the unit of work.

| Audit field | Candidate field | Notes |
|---|---|---|
| `_id` (streaming row id) / deterministic sha256 digest of (actor, repo, action, `@timestamp`, `created_at`) | `source_event_id` | `sha256:<16 hex>` fallback when the export drops row ids |
| `@timestamp`, else `created_at` | `event_time` | UTC ISO |
| `actor` | `actor` | required |
| `action` | `action` | lower-cased verbatim (`git.clone`, `protected_branch.update_ref`, …) |
| `repo` (string or `{name}`) | `resource` | |
| `hashed_token` | `session_binding` | fingerprint only, never the token; `None` when absent |
| `request_id` | `unverified_linkage` | `github.request_id:<id>`; never correlation-eligible |
| `actor_is_bot`, `actor_is_agent`, `token_scopes`, `programmatic_access_type`, `integration`, `application_client_id`, `business_category` | `raw_ref` | default declared passthrough |

## The two conventions (precise)

1. **AWS binding convention.** The Raucle gate mediates execution on an
   IAM assumed role and sets, per receipt,
   **`roleSessionName = 'oaa-<receipt_hash_prefix>'`** where
   `receipt_hash_prefix` is the 12 leading chars of the receipt's
   `receipt_hash`. CloudTrail's `userIdentity.principalId` echoes the
   session name, so `reconcile` matches `candidate.session_binding ==
   'oaa-' + receipt_hash[:12]` (the token is derivable from the index row;
   rows may also carry an explicit `convention_token`). Binding equality →
   `matched` at **high** confidence.
2. **GitHub binding convention.** GitHub audit events carry no client-supplied
   correlation field, so the gate issues a per-receipt credential and records
   the credential's **fingerprint** (`hashed_token`, SHA-256 of the token —
   never the token itself) alongside the `receipt_hash` in the receipt index
   row (`hashed_token` field). The audit event repeats the same fingerprint.
   Binding equality → `matched` at high confidence. A credential issued
   outside that convention degrades every GitHub match to time+actor
   (`matched_degraded`).

## Reconciliation semantics (ADR-0002 states × ADR-0004 bypass)

| State | Meaning | Confidence | Notes |
|---|---|---|---|
| `matched` | binding-token equality | high | strongest available evidence |
| `matched_degraded` | time-window + actor, no binding | medium | flagged lower confidence in notes |
| `bypass_suspected` | privileged op, no receipt in window, past grace | high | SEC-009; observed discrepancy only, **never intent attribution** |
| `receipt_only_gap` | receipt, no audit event | low | `evidence_gap` per ADR-0004 — NOT proof of non-execution |
| `receipt_missing` | unprivileged op, no receipt | low | audit-coverage gap, not a bypass finding |
| `duplicate` | N deliveries of one logical candidate or one receipt_hash collapsed | medium | provenance of every delivery preserved |
| `ambiguous` | multiple distinct receipts claim one candidate (or vice versa) | low | never silently resolved; human review |

Confidence classes are recorded per record; `pending` counts open
(in-grace) records via the explicit `at` instant. Findings never state "the
agent bypassed the gate" — tests assert the wording.

## Retention notes

- **CloudTrail:** management events 90 days standard; CloudTrail Lake up to
  7–10 years (longer windows cost storage; the reconcile window must still
  tolerate lake export batching).
- **GitHub audit log:** retained indefinitely on paid plans (window scales
  with org billing tier). No archive-loss concern for the export surface.

## Semantics locked in tests (`tests/audit_sources/`)

| Scenario | Outcome |
|---|---|
| binding-equality (AWS derived `oaa-` token; GitHub `hashed_token`) | `matched`, high, `match_method="binding"` |
| no binding, same actor, in-window | `matched_degraded`, medium, notes flag lower confidence |
| privileged op, no receipt | `bypass_suspected`, high, SEC-009 wording, no intent attribution |
| unprivileged op, no receipt | `receipt_missing` (coverage gap, not bypass) |
| receipt, no candidate | `receipt_only_gap`, low, "NOT proof of non-execution" |
| duplicate deliveries (either side) | collapse to `duplicate`, provenance preserved |
| 2 distinct receipts on 1 candidate | `ambiguous`, low, never resolved |
| in-grace (`at` near events) | `pending` count, no terminal records |
| window boundary (121 s) | no match; bypass/`receipt_only_gap` pair |
| no-payload invariants | `raw_ref` keys ⊆ `declared_raw_fields`; `request_id` ≠ binding |

## What remains

- **Live fetchers/collectors** (deployment glue): CloudTrail Lake query/S3
  export pull, GitHub audit-log API pagination and export scheduling. They
  belong to the companion ingest layer (ADR-0001 vantage rules), not this
  offline library.
- **MCP gateway connector:** the MCP gateway is a third vantage candidate; a
  normalizer for its audit stream (`oaa_audit_sources` currently ships
  `aws_cloudtrail` + `github_audit` only).
- **AEB effects leg:** reconcile the Application Effects Broker leg once its
  effect records expose a receipt-linked surface.
- **EP-AEC composition of tool-side evidence:** composing these candidates
  into EP-AEC envelopes for verification remains composition work, not
  connector work.

## Gate

`.venv/bin/ruff format --check .` + `ruff check .` clean repo-wide;
`scripts/local-gate.sh --warn` shows no production findings; baseline 248
tests green + K2 suite green (counts printed in the run transcript).