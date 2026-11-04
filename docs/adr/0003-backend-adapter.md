# ADR 0003: Trace backend adapter and deployment-first choice

Status: Draft (pending review)
Date: 2026-11-04

## Context

The backend capability matrix (findings at `~/Projects/oaa-spike-4nov/backend-capability-matrix.md`) verified at pinned refs, 2026-11-04:

- Langfuse v4.74.0 (commit `0845eed`): core MIT Expat (copyright ClickHouse Inc.), EE carve-out under `ee/`, `web/src/ee/`, `worker/src/ee/`, `packages/shared/src/server/ee/` governed by a proprietary Enterprise License that activates behind a licence key or cloud-region env var. RBAC lives in the MIT core (`packages/shared/src/features/rbac/`); SSO/SCIM, audit logs, admin API, data retention, data masking, FIPS sit in the EE carve-out. Full datasets, experiments and scores API are core. Six-service self-host stack: web, worker, ClickHouse, MinIO, Redis, Postgres.
- Phoenix v21.0.0: whole-repo Elastic License 2.0. Free self-host and internal use; prohibited as a hosted/managed service offering substantial functionality. Lightest footprint (2 containers, Postgres). OAuth2/OIDC SSO in core.
- SigNoz v0.99.0: MIT core plus `ee/` and `cmd/enterprise/` carve-outs. Uptrace v2.1.0-rc.2: AGPL-3.0 (copyleft caution for an Apache-2.0 companion).
- OpenInference compatibility with Langfuse is unverified and must be probed.

Decisions already taken (Craig, 4 Nov): internal self-hosted first, open-source release later; Langfuse-first; Phoenix ELv2 acceptable in internal model only.

## Decision

1. **Backend-agnostic adapter interface, Langfuse-first implementation.** The companion talks to trace backends through a narrow adapter interface: ingest verification (round-trip fidelity), read for investigation UI, score attachment for evaluation results. Langfuse v4.74.0 OSS is the first adapter. A second adapter (Phoenix or Tempo-class) is built only if the demo of portability is demanded in practice.

2. **Evidence index stays outside the backend.** Receipts, verification state and correlation metadata never enter any trace backend's own storage. Only backend-agnostic references (receipt_hash, evidence URLs) cross the boundary. This keeps every backend swappable and keeps canonical evidence under companion custody.

3. **Authentication posture, self-host.** Operate with local auth plus RBAC (verified in MIT core) for the internal pilot. SSO requirements, if raised by a pilot organisation, trigger an explicit licence decision (EE licence versus alternative) rather than silent scope growth. This is a named decision gate, not a default.

4. **De-risking probes required before OBS-01 UI work**, per the matrix:
   - Round-trip fidelity: attributes with controlled redaction survive Langfuse ingestion without loss or unintended enrichment.
   - Score attachment: evaluation scores attach and read back with version metadata.
   - Ingest behaviour under collector outage: bounded retry, visible loss metrics. Note (verified 4 Nov, P3): the stock OTLP exporter silently drops spans on connection refused; the companion must ship its own bounded-retry exporter with explicit loss counters and a post-recovery marker span. Stock behaviour is an accepted-residual, not a control.

**Deployment gate (added 4 Nov, from P1 finding):** Langfuse v4.74.0 self-host defaults to `LANGFUSE_MIGRATION_V4_WRITE_MODE=events_only`, which disables the legacy read API. The companion requires `dual` mode; set it explicitly in deployment configs and record it in the ops runbook. Any Langfuse version bump must recheck this variable.

5. **Licence hygiene for the companion.** Companion code stays Apache-2.0. No code copying from Phoenix (ELv2) or Langfuse EE directories. Dependency manifests and SBOM maintained from the first commit; the matrix is re-verified at each version bump, since this environment moves fast (Langfuse crossed to v4 between plan drafting and this review).

## Consequences

- The licence surface is now precise instead of feared: the companion only depends on MIT-core surfaces, and the ee/ boundary is a runtime gate, not a code dependency.
- Six-service stack is the real operational footprint; the cost model uses it, not marketing numbers.
- A backend swap later costs one adapter implementation plus fidelity probe reruns.

## Alternatives considered

- Phoenix-first: rejected for the primary path (ELv2 coupling to a later Apache-2.0 release, heavier custom UI work), retained as the documented secondary target.
- Generic OTel backend (Tempo plus ClickHouse): rejected for the MVP (no eval/dataset layer, more custom work) but noted as the strict-OSI fallback.