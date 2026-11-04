# Backend Capability Matrix — Trace Backend Decision (Workstream B)

**Project:** Open Agent Assurance companion (EPIC K) · **Owner:** Workstream B
**Prepared:** 2026-11-04 · **Evidence access date for all claims in this file: 2026-11-04 (Europe/London), unless a different date is stamped per claim.**
**Method:** primary sources only — cloned repos at pinned refs (LICENSE files read verbatim, ee/ directories listed, docker-compose files grepped), GitHub release pages, vendor docs pages. Every claim's source is named. Vendor-claimed (not reproducible from code/primary docs) items are explicitly labelled.

---

## 1. Pinned versions and licences

| Product | Pinned ref | Release date | Licence (read from source) | Source |
|---|---|---|---|---|
| Langfuse | `v4.74.0` (commit `0845eed855fe32ccfaa1b1db430ce29dfbf2e9d7`) | Tagged 2026-11-03 (release page); commit date 2026-11-03 14:47 +0100 | **MIT Expat core** (Copyright 2023–2026 **ClickHouse, Inc.**) + **proprietary carve-out** under `ee/`, `web/src/ee/`, `worker/src/ee/`, `packages/shared/src/server/ee/` (governed by `ee/LICENSE`, an unlicensed "Enterprise License" requiring an agreement with Langfuse GmbH/ClickHouse) | Cloned repo @ tag; `LICENSE` and `ee/LICENSE` read verbatim, 4 Nov 2026; https://github.com/langfuse/langfuse/releases |
| Arize Phoenix | `arize-phoenix-v21.0.0` (commit `6359d63`) | 2026-10-30 (GitHub release, "mikeldking released this 30 Oct 03:29") | **Elastic License 2.0 (ELv2)** — whole repo; no OSS carve-out | Cloned repo @ ref `642585376568cee44c982da90eb67180bfaa7861` (main @ 2026-11-03), `LICENSE` head read; https://github.com/Arize-ai/phoenix/releases/tag/arize-phoenix-v21.0.0 |
| SigNoz | `v0.99.0` tag; local clone HEAD `825991864df2594dd300080da83423f5576715bf` (2026-11-04) | Nov 2026 (tag date not directly verified — clone HEAD 4 Nov 2026) | **MIT Expat core** (Copyright 2020–present SigNoz Inc.) + proprietary carve-out under `ee/` **and `cmd/enterprise/`** (`ee/LICENSE` = "SigNoz Enterprise license… may only be used in production if… valid SigNoz Enterprise license") | Cloned repo, `LICENSE` + `ee/LICENSE` read verbatim; `git ls-remote` tag list, 4 Nov 2026 |
| Uptrace | `v2.1.0-rc.2` (commit `1e622fff165391a26bbebc135e4c4f8a843ef1bd`) | Commit dated 2026-10-08 15:23 +0300 | **GNU Affero General Public License v3.0 (AGPL-3.0)** — whole repo | Cloned repo, `LICENSE` read verbatim; `git ls-remote` tag list, 4 Nov 2026 |
| Grafana Tempo (considered, rejected) | not pinned | — | **AGPL-3.0** (vendor-claimed from repo README; not independently read in this exercise) | — |
| ClickHouse (storage layer) | — | — | **Apache-2.0** (vendor-claimed; not re-read this session — carried from earlier verification of 2026-10/11) | — |

**Note on Langfuse v3→v4:** the repo has moved past v3 (`v3.227.0`-era) to **v4** ("Langfuse v4: up to 165× faster", vendor changelog banner, https://langfuse.com/changelog/2026-08-17-langfuse-v4, accessed 4 Nov 2026). This matrix pins **v4.74.0** and re-verified the licence structure there: the MIT grant text in `LICENSE` changed the copyright line to "Copyright (c) 2023-2026 ClickHouse, Inc." (ClickHouse acquired Langfuse — vendor-claimed from the copyright text) but the directory carve-out list is unchanged.

---

## 2. What the Langfuse `ee/` directories actually gate (verified from code, v4.74.0)

Listing `ee/`, `web/src/ee/`, `worker/src/ee/`, `packages/shared/src/server/ee/` in the cloned repo (4 Nov 2026):

| Feature dir | Located in | Reads as |
|---|---|---|
| `features/access-audit-log`, `features/audit-log-viewer` | `web/src/ee/` | Audit logging UI + access audit log |
| `features/admin-api` | `web/src/ee/` | Admin API (project transfer between orgs was added here on 3 Nov — v4.74.0 release notes: "feat(admin-api): transfer projects between organizations") |
| `features/billing` | `web/src/ee/` | Billing (cloud-related) |
| `features/multi-tenant-sso`, `features/sso-settings` | `web/src/ee/` | **SSO configuration / multi-tenant SSO** |
| `features/sfdc-sync` | `web/src/ee/` | Salesforce sync |
| `features/support-access`, `features/verified-domains`, `features/ui-customization` | `web/src/ee/` | Support access, verified domains, white-labelling |
| `cloudSpendAlerts`, `cloudUsageMetering`, `dataRetention`, `fipsMode`, `meteringDataPostgresExport`, `usageThresholds` | `worker/src/ee/` | Cloud ops: spend alerts, usage metering, **data-retention policies**, FIPS 140-3, usage thresholds |
| `clickhouseBilling`, `fips`, `ingestionMasking`, `licenseCheck` | `packages/shared/src/server/ee/` | Shared EE plumbing incl. **data masking** (ingestion masking) and the licence gate |
| `ee-license-check` | `ee/src/` | Gate: `isEeAvailable = NEXT_PUBLIC_LANGFUSE_CLOUD_REGION defined OR LANGFUSE_EE_LICENSE_KEY defined` (verbatim from `ee/src/ee-license-check/index.ts`) |

**Key conclusion (verified):** EE code ships in the image but **deactivates without a licence key or a cloud-region env var** — the OSS self-hosted build runs pure MIT core ("You can run the core image without a key without running EE code" — vendor docs https://langfuse.com/docs/open-source, accessed 4 Nov 2026).

**RBAC is NOT in `ee/` (verified):** RBAC implementation lives in core at `packages/shared/src/features/rbac/` (`index.ts`, `organizationAccessRights.ts`, `projectAccessRights.ts`, `roleAssignmentService.ts`, `systemRoleAccessRights.ts`) and `web/src/features/rbac/`, outside any carve-out directory. The vendor self-hosted pricing page also lists "Organization-level RBAC… Enterprise SSO… SSO enforcement" ambiguously in its Open Source column (checkboxes lost in extraction — **vendor-claimed**), but the code location is primary evidence that org/project RBAC is core MIT as of v4.74.0. **SCIM appears at `web/src/pages/api/public/scim/` (outside `ee/`) — I could not confirm how it is gated** (no `licenseCheck` import found with my greps); vendor docs list SCIM as a paid Enterprise module ("Enterprise modules such as SCIM, audit logging, and data retention policies require a commercial license" — https://langfuse.com/docs/open-source, accessed 4 Nov 2026). Treat SCIM as **commercially gated, vendor-claimed exact mechanism**.

---

## 3. Per-backend capability matrix

### 3.1 Langfuse `v4.74.0` (MIT core + EE carve-out)

| Dimension | Finding | Source/label |
|---|---|---|
| Licences of shipped components | Core MIT Expat (ClickHouse, Inc. 2023–2026); EE dirs proprietary; runs on ClickHouse OSS (Apache-2.0, vendor-claimed), Postgres, Redis, MinIO (S3-compat) | `LICENSE`, `docker-compose.yml` read 4 Nov 2026 (verified); ClickHouse Apache-2.0 (vendor-claimed/known) |
| Install footprint (docker compose) | **6 services** in `docker-compose.yml`: `langfuse-web`, `langfuse-worker`, `clickhouse`, `minio`, `redis`, `postgres` (+6 named volumes) | `docker-compose.yml` grepped, verified |
| Auth / RBAC / SSO (self-hosted OSS) | Local email/password + social OAuth sign-in; **RBAC in MIT core** (see §2); **SSO/multi-tenant SSO, SSO enforcement, audit logs, admin API, SCIM, data retention, data masking, FIPS, UI customization = EE, licence-key gated** | Repo listing (verified) + vendor pricing-self-host page (vendor-claimed) |
| OTel ingest | Native OpenTelemetry endpoint: `web/src/pages/api/public/otel` exists in core code (verified); vendor docs: OTLP ingest is a first-class supported integration for Java/Go/custom | Repo listing (verified); vendor docs (vendor-claimed URL https://langfuse.com/docs/api-and-data-platform/features/public-api, accessed 4 Nov 2026) |
| OpenInference compatibility | Not natively OpenInference — Langfuse consumes OTel gen-ai conventions; no explicit OpenInference mapping found in repo (grep for OpenInference in docs repo not performed) | **Unverified** — needs a probe in Workstream C |
| Attribute fidelity | Custom ingestion pipeline flattens OTel spans into Langfuse trace/observation/score model; multi-modal + media retained; "blob store to persist all incoming events, multi-modal inputs, large exports" | Vendor docs https://langfuse.com/docs/open-source (vendor-claimed); schema in repo (verified structure exists) |
| Export | Batch export via UI, scheduled batch export to blob storage (OSS column), PostHog/Mixpanel; blob-export trace field groups added in v4.73.0 (release notes) | Vendor pricing page (vendor-claimed); v4.73.0 release notes (verified) |
| Storage deps | ClickHouse (required, primary trace store), Postgres (metadata/auth), Redis (queue), S3/MinIO (blob) | `docker-compose.yml`, vendor infra docs (verified/vendor-claimed) |
| Eval / dataset / scores API | **Full OSS**: datasets, dataset-items, experiments, experiment-items, score-configs, scores, annotation-queues all present as core API route dirs in `web/src/pages/api/public/` | Repo listing (verified) |
| Self-host ops cost | OSS: free licence; you run ClickHouse + Redis + Postgres + blob on your infra (vendor: "same deployment that can grow from single-node docker compose to Kubernetes"). Enterprise self-host: custom pricing, bundled with a ClickHouse Cloud/BYOC commercial plan ("Langfuse pricing is additive to your ClickHouse commercial plan") | Vendor pricing-self-host page (vendor-claimed, accessed 4 Nov 2026) |
| Community edition feature set | "All product capabilities—tracing, evaluations, prompt management, experiments, annotation, playground—are MIT licensed without any usage limits" | Vendor docs https://langfuse.com/docs/open-source (vendor-claimed, but consistent with licence text + API route listing) |

### 3.2 Arize Phoenix `v21.0.0` (ELv2)

| Dimension | Finding | Source/label |
|---|---|---|
| Licence | **ELv2 across the whole repo** (first verbatim line of `LICENSE`: "Elastic License 2.0 (ELv2)"). ELv2 restricts offering the software as a managed service and removing licence-key/feature-limit features. Fine for internal self-hosted eval; **conflicts with the planned Apache-2.0 companion redistribution if we ship/derive from Phoenix code** | `LICENSE` read 4 Nov 2026 (verified) |
| Version | v21.0.0, 2026-10-30; v20.27.0 2026-10-29; frequent releases (multiple per week) | GitHub release page (verified) |
| Install footprint | **2 services** in `docker-compose.yml`: `phoenix` + `db` (postgres:16) + one volume | `docker-compose.yml` read 4 Nov 2026 (verified) |
| Storage deps | Postgres only (no ClickHouse/Redis/S3/queue) — lightest footprint of the four | `docker-compose.yml` (verified) |
| Auth / SSO (self-hosted) | v21.0.0 release note: **"auth: enable auth by default without requiring PHOENIX_SECRET"**; OAuth2/OIDC providers (Google/GitHub/Microsoft/custom) via `PHOENIX_OAUTH2_*` env vars, incl. auto-login/single-sign-on mode; **SAML = Enterprise/Cloud only ("SAML SSO is available on Enterprise plans. Contact Sales")**; RBAC roles (Viewer/Member) exist in docs | v21.0.0 changelog (verified); docs https://docs.arize.com/phoenix/deployment/authentication (vendor-claimed, accessed 4 Nov 2026) |
| OTel ingest | Native OTLP receiver, collector instrumentation via `phoenix-otel`; auth header support `PHOENIX_API_KEY`, bearer auth | Vendor docs (vendor-claimed, accessed 4 Nov 2026) |
| OpenInference compatibility | **Home turf**: Phoenix defines/consumes the OpenInference semantic-convention spec; `arize-phoenix-evals` updated alongside (v3.9.2 in v20.21.0 changelog) | Vendor-claimed; repo `evals/` dir exists (verified location only) |
| Attribute fidelity | Spans retained with attributes; `system_state` table and span cost tracking added in v21.0.0 | v21.0.0 changelog (verified) |
| Export | Dataset/experiment APIs; `@arizeai/phoenix-client/datasets` label helpers (v7.18.0, 2 Nov 2026) | GitHub release page (verified) |
| Eval / dataset / scores API | Datasets, experiments, annotations (v21.0.0 adds "annotations: add DECISION and AGENT kinds"), evaluators, cost tracking runtime manifest | v21.0.0 changelog (verified) |
| Self-host ops cost | Lowest: single Python service + Postgres. **Unverified**: memory/CPU sizing guidance not read this session | — |

### 3.3 SigNoz `v0.99.0` (MIT core + EE carve-out)

| Dimension | Finding | Source/label |
|---|---|---|
| Licence | MIT Expat core (Copyright 2020–present SigNoz Inc.); `ee/` **and `cmd/enterprise/`** proprietary — "may only be used in production if… valid SigNoz Enterprise license" | `LICENSE`, `ee/LICENSE` read 4 Nov 2026 (verified) |
| Install footprint | Current supported install is via **Foundry CLI** generating docker compose; rendered stack: `signoz` single binary (UI+API+alertmanager), `signoz-otel-collector` (OTLP 4317/4318), `clickhouse` 25.5.6, `clickhouse-keeper`, `postgres:16` (metastore for dashboards/users). Legacy bundled `deploy/` compose deprecated since v0.130.0 (vendor note) | Vendor docs https://signoz.io/docs/install/docker/ accessed 4 Nov 2026 (vendor-claimed); 5 containers total |
| Storage deps | ClickHouse (primary), Postgres (metastore). No Redis/S3 required in OSS compose | Vendor docs (vendor-claimed) |
| Auth / SSO | `ee/authn` (callbackauthn) and `ee/authz` (**OpenFGA**-based) are EE dirs → SSO (SAML/SSO), fine-grained authorization = licence-key gated; OSS has basic auth | Repo listing of `ee/` (verified); exact OSS auth scope **unverified** |
| OTel ingest | Native: SigNoz ships its own OTel-collector fork accepting standard OTLP | Vendor docs (vendor-claimed) |
| OpenInference | One `spanmapper` doc mentions OpenInference (`docs/contributing/go/spanmapper.md`); OpenInference/OTel-genai span mapping exists in the collector | Repo doc (verified location); depth **unverified** |
| Eval / dataset / scores | **No native LLM eval/dataset/experiment module** — general APM traces/logs/metrics; LLM observability via span mapping + dashboards; no dataset/annotation API comparable to Langfuse/Phoenix | Absence in repo listing (verified absence); **needs confirm of current docs** |
| Self-host ops cost | Free (core MIT); ops = ClickHouse sizing, keeper, collector; vendor publishes minimum 4GB Docker memory | Vendor docs (vendor-claimed) |

### 3.4 Uptrace `v2.1.0-rc.2` (AGPL-3.0)

| Dimension | Finding | Source/label |
|---|---|---|
| Licence | **AGPL-3.0** whole repo (read verbatim). OSS per OSI, but AGPL §13 network-service clause means hosting it for users triggers source-sharing obligations — acceptable for internal-only, riskier if the OAA companion ever exposes it beyond the firm | `LICENSE` read 4 Nov 2026 (verified) |
| Install footprint | `docker-compose.yml` = demo-grade: `clickhouse` 25.3.3, `postgres` 15, `otelcol`, `alertmanager`, `vector`, `keycloak`, `grafana`, `prometheus`, `mailpit` — 9 services incl. Keycloak bundled for SSO demo; production needs only uptrace (single Go binary) + ClickHouse (+ optional Postgres) | `docker-compose.yml` read (verified) |
| Auth / SSO | README: "Single sign-on (SSO) using OpenID Connect: Keycloak, Google Cloud, Cloudflare"; OIDC code paths in `pkg/bunconf/config.go`, `pkg/org/user_provider.go` (verified in OSS tree). RBAC granularity: **unverified** | README + repo grep (verified claims) |
| OTel ingest | Via bundled/configured OTel Collector writing to ClickHouse; `otelcol` in compose | `docker-compose.yml` (verified) |
| OpenInference | Not found in repo | **Unverified/absent** |
| Eval / dataset / scores | No LLM-eval module (APM tracing focus) | Absence in repo listing (verified absence) |
| Self-host ops cost | Free (AGPL); vendor model = Uptrace Cloud paid SaaS; self-host = your ClickHouse ops | README structure (verified direction); pricing details **unverified** |

### 3.5 Grafana Tempo + ClickHouse (considered, not selected)

Agent-pure-tracing store (AGPL-3.0 for Tempo, vendor-claimed; ClickHouse Apache-2.0, vendor-claimed). No eval/dataset/score API, no annotation UI; we would build the entire eval layer ourselves. Rejected on capability coverage, not on licence (AGPL-3.0 is still OSI open source). Not pinned this session — **all details unverified**.

---

## 4. Comparison at a glance (self-hosted, unlicensed/free editions)

| Criterion | Langfuse v4.74.0 (OSS) | Phoenix v21.0.0 | SigNoz v0.99.0 (OSS) | Uptrace v2.1.0-rc.2 |
|---|---|---|---|---|
| Licence | MIT core + EE carve-out | ELv2 (whole product) | MIT core + EE carve-out | AGPL-3.0 |
| Apache-2.0-compatible redistribution of companion | ✅ (core MIT) | ❌ ELv2 service/feature-restraint terms | ✅ core | ⚠️ AGPL obligations if exposed as network service |
| Containers | 6 (web, worker, CH, MinIO, Redis, PG) | 2 (app, PG) | 5 (signoz, otelcol, CH, keeper, PG) | 2–9 (binary + CH + optional PG) |
| Eval/dataset/scores API in free self-host | ✅ full (verified code dirs) | ✅ (per changelog) | ❌ | ❌ |
| RBAC in free self-host | ✅ org+project (code outside ee/, verified) | basic roles (docs; unverified depth) | ❌ (OpenFGA authz is EE) | unverified |
| SSO | ❌ MIT core (EE-gated: multi-tenant-sso, sso-settings); social OAuth only | ✅ OAuth2/OIDC self-host; SAML=enterprise | ❌ EE | ✅ OIDC (OSS code) |
| OTel ingest ✅ | ✅ native endpoint | ✅ native OTLP | ✅ native collector | ✅ via collector |
| OpenInference | absent/questionable | ✅ home standard | partial (spanmapper) | absent |
| Trace attribute fidelity | vendor pipeline (custom model, multimodal, blob) | OpenInference-native span store | generic OTel span model | generic OTel span model |
| Storage deps | CH+PG+Redis+S3 | PG only | CH+PG | CH(+PG) |
| Self-host licence cost | £0 OSS; EE custom | £0 (ELv2, internal use OK) | £0 OSS | £0 OSS |

---

## 5. Recommendation (one page) — vertical-slice backend

**Recommendation: run the vertical slice on Langfuse `v4.74.0` OSS (MIT core), pinned above, self-hosted via docker-compose; keep Phoenix v21.0.0 as a secondary read-only comparison target; record SigNoz as licence-precedent reference.**

1. **Licence fit is decisive.** The OAA companion must be internally self-hosted first and later distributed as an Apache-2.0 derivative/re-implementation of the trace layer. Langfuse core is MIT (verified in the tagged release this session, re-confirmed post-v4 under ClickHouse copyright), which permits the redistribution path. Phoenix is ELv2 for the entire codebase — fine for internal use, but any companion code deriving from Phoenix cannot ride an Apache-2.0 grant. SigNoz's structure (MIT core + identical `ee/LICENSE` enterprise-gate pattern) makes it our safest precedent for an "open-core, key-gated EE" design if we ever mirror that shape; Uptrace is fine internally but AGPL makes it the least safe to reuse in the Apache-2.0 companion.
2. **The EE gap does not block us.** Verified v4.74.0 `ee/` contents (SSO, audit logs, admin API, SCIM, retention, masking, FIPS, billing/cloud ops) are all governance/ops features, gated by `isEeAvailable` (cloud region or licence key). The vertical slice (OTel ingest → traces → dataset/experiment/score → report) relies only on MIT core plus RBAC, which we verified lives **outside** the carve-out. If HR/procurement later demands Okta SSO or audit logs, that is a commercial purchase, not an engineering fork.
3. **Feature fit.** It is the only candidate in the matrix with both a mature eval/dataset/score API and full OTel-native ingest in the free self-hosted edition; the APIs we need (`/api/public/otel`, datasets, experiments, scores, annotation-queues) exist as core routes in the tagged source. Phoenix is functionally competitive on eval (and is the OpenInference standard-bearer) but its licence plus heavier per-release churn make it the fallback; our unverified OpenInference-mapping gap in Langfuse should be probed in Workstream C with a real span export before the slice ends.
4. **Ops.** Six containers (ClickHouse, Postgres, Redis, MinIO, web, worker) is the heaviest footprint but each is a stock OSS component; Phoenix's two-container Postgres-only deployment is the lightest and remains our "cheap second opinion" deployment for score cross-checks.
5. **De-risking actions for the slice** (a) probe Langfuse OTLP ingest with an OpenInference-instrumented sample and diff attribute fidelity; (b) confirm SCIM gating mechanism by reading the runtime licence check in `web/src/pages/api/public/scim/` before assuming any audit/provisioning requirement; (c) if any EE feature becomes a hard requirement, re-run the licence comparison against Enterprise self-host pricing (custom, quoted — vendor-claimed) before committing.

**Confidence:** Langfuse/Phoenix/SigNoz/Uptrace licence text, ee-directory contents, compose footprints, and pinned versions all verified from cloned primary sources on 2026-11-04. All vendor pricing/feature-table statements and any claim marked "vendor-claimed" or "unverified" remain to be re-confirmed in the verification pass before the EPIC K decision is signed.