# Runtime and optional dependency inventory

**Status:** Inventory baseline; not yet a complete deployed-environment SBOM  
**Reviewed:** 2026-11-26  
**Purpose:** Identify authoritative dependency declarations, lockfiles, build/install paths and deployment images so release evidence can be scoped without treating development tooling as shipped runtime.

## Scope and interpretation

This inventory distinguishes four different things:

1. **Published Python distributions** — dependencies declared in each distribution's `[project]` metadata and the exact wheel/sdist produced by the release workflow.
2. **Deployable Python services** — dependencies installed to run source-based services, including their optional serving extras and lockfiles.
3. **Reference container images** — image identities declared in the packaged Compose deployment and resolved to immutable registry digests by the container SBOM workflow.
4. **Development and CI environments** — tools and packages installed to run tests, linting, fixture generation or SBOM tooling. These are not automatically product runtime dependencies.

An empty optional extra is not evidence that an integration is dependency-free. Where READMEs describe a pinned worktree or locally installed dependency that is absent from project metadata, this is recorded as a manifest gap rather than silently inferred into a release SBOM.

## Python distributions built by the release workflow

`.github/workflows/python-distribution-sbom.yml` currently builds one wheel and one sdist for each of these six distributions, then generates a separate CycloneDX SBOM for each exact file:

| Distribution | Manifest | Declared runtime dependencies | Optional metadata / caveat |
|---|---|---|---|
| `oaa-raucle-adapter` | `packages/raucle-adapter/pyproject.toml` | None | `raucle=[]` placeholder. README documents Raucle 0.23.6 / git `645f5de` via worktree or PyPI; that pin is not represented as a resolved extra. |
| `oaa-instrumentation` | `packages/instrumentation/pyproject.toml` | None | `otel=[]` placeholder. README describes OTel SDK/exporter and PyYAML as optional, but they are not declared/resolved by this manifest. |
| `oaa-ep-aec` | `packages/ep-aec/pyproject.toml` | None | `raucle=[]` placeholder. README describes optional Raucle 0.23.6 / git `645f5de` and adapter integration; not resolved in this manifest. |
| `oaa-audit-sources` | `integrations/audit-sources/pyproject.toml` | None | `dev` contains pytest and Ruff. `integrations/audit-sources/uv.lock` locks this dev environment. |
| `oaa-langgraph-adapter` | `integrations/langgraph-adapter/pyproject.toml` | None | `raucle=[]` placeholder; `dev` contains pytest and Ruff. README says LangGraph/LangChain are not required for the core middleware path. Lockfile: `integrations/langgraph-adapter/uv.lock`. |
| `oaa-correlation` | `services/correlation/pyproject.toml` | None | Manifest states stdlib-only; no dedicated lockfile found. |

The build workflow currently proves the contents of these six wheel/sdist pairs. It does not prove that every service or optional deployment overlay is represented by these distributions.

## Source-based Python services and libraries

These project manifests exist in the repository but are not included in the six-distribution build matrix:

| Component | Manifest | Declared runtime set | Lockfile | Release/SBOM status |
|---|---|---|---|---|
| Console | `services/console/pyproject.toml` | `fastapi==0.118.3`, `httpx==0.28.1`; `serve` adds `uvicorn==0.38.0` | `services/console/uv.lock` | Source service; no wheel/sdist SBOM job currently. |
| Investigation UI | `services/investigation-ui/pyproject.toml` | `fastapi==0.118.3`, `httpx==0.28.1`; `serve` adds `uvicorn==0.38.0` | `services/investigation-ui/uv.lock` | Source service; no wheel/sdist SBOM job currently. |
| Quality evaluator | `services/quality/pyproject.toml` | None; manifest and README describe stdlib-only evaluator | None found | Source library; no distribution SBOM job currently. |

The console and investigation UI lockfiles are the authoritative resolved sets for their declared manifests. They should be scanned independently as deployment environments if those services are shipped or installed separately. Their service lockfiles must not be merged into the six distribution SBOMs. `tests/security/pyproject.toml` is a nested Ruff-only configuration (no `[project]` metadata or runtime dependencies), not a distributable package or deployment environment.

## Optional integrations and non-manifest dependencies

The following are explicit inventory gaps requiring a product decision before they can be called supported runtime extras:

- **OpenTelemetry instrumentation:** the README identifies `opentelemetry-sdk`, `opentelemetry-exporter-otlp-proto-http` and `pyyaml`, but `otel=[]` in the package metadata. CI currently installs these packages by unpinned names. The package needs a declared extra and a lock/constraints source before a reproducible optional-runtime SBOM can be claimed.
- **Raucle adapter / EP-AEC integration:** READMEs document Raucle 0.23.6 at git `645f5de` (or a matching PyPI release), while their `raucle=[]` extras are empty. The pinned worktree is operational guidance, not a dependency resolution artifact. Convert this into a verifiable immutable source pin or a verified package pin before claiming the extra is locked.
- **LangGraph adapter:** the package intentionally avoids requiring LangGraph/LangChain for the core middleware path and conditionally integrates when available. No runtime extra currently resolves those packages. Do not add them to the base runtime inventory merely because the integration name contains LangGraph.
- **Audit sources:** pytest and Ruff are development-only dependencies in the `dev` extra and lockfile; they are not runtime dependencies of the published connector.
- **CI root environment:** `.github/workflows/ci.yml` installs Ruff, pytest, cryptography, PyYAML, FastAPI, HTTPX, OpenTelemetry SDK/exporter and jsonschema by imperative unpinned pip commands. This is a test environment, not a production lockfile. Pinning and scanning it is a separate CI-supply-chain task; it must not be conflated with product runtime.

## Reference deployment images

`deploy/reference/docker-compose.yml` declares seven image-bearing services and is the source for the seven-entry matrix in `.github/workflows/container-image-sbom.yml`:

| Compose service | Declared image |
|---|---|
| `langfuse-worker` | `docker.langfuse.com/langfuse/langfuse-worker:4.74.0` |
| `langfuse-web` | `docker.langfuse.com/langfuse/langfuse:4.74.0` |
| `clickhouse` | `docker.io/clickhouse/clickhouse-server:26.3.62.3` |
| `minio` | `cgr.dev/chainguard/minio` |
| `redis` | `docker.io/redis:7` |
| `postgres` | `docker.io/postgres:17` |
| `evidence-index` | `docker.io/library/python:3.12-alpine` |

The workflow pulls each declared image, captures the registry-reported SHA-256 digest and runs Syft against the digest reference. The MinIO, Redis and Postgres tags are not version-qualified immutable references in the Compose file; the workflow's resolved digest is therefore essential evidence for each run. The packaged reference Compose file is covered; `deploy/compose/docker-compose.yml` is an earlier six-image spike and is not an additional production artifact.

The optional OTel collector described in `deploy/reference/README.md` is not part of the shipped Compose stack. If it becomes a supported deployment overlay, it needs its own pinned image and SBOM entry before inclusion in release claims.

## Coverage matrix and remaining actions

| Dependency surface | Authoritative source | Current evidence | Remaining action |
|---|---|---|---|
| Six Python distributions | Each distribution's `pyproject.toml` + built wheel/sdist | Per-file SBOM and digest binding in Python distribution workflow | Keep matrix synchronized with manifest inventory; add runtime extras only when declared and resolved. |
| Console and investigation UI | Each service `pyproject.toml` + service `uv.lock` | Lockfiles present; not in distribution matrix | Add per-service lockfile SBOM scans to release evidence if these source services are shipped. |
| OAA quality/correlation services | Their `pyproject.toml` manifests | Declared stdlib-only; no dedicated lockfiles | Confirm whether source deployment is supported; if yes, build/install and scan the exact deployment environment. |
| Optional OTel runtime | README + currently imperative CI install | No declared extra/lockfile | Declare exact extra constraints, lock it, and scan the resolved extra. |
| Raucle integration pin | READMEs / worktree instructions | Version/commit text only; empty extras | Verify package/tag-to-commit identity and encode an immutable dependency source. |
| Reference Compose images | `deploy/reference/docker-compose.yml` | Seven digest-resolved image SBOMs | Preserve digest evidence and decide on durable archive. |
| CI/test toolchain | `.github/workflows/ci.yml` | Unpinned imperative installs | Create a dedicated pinned CI dependency lock if CI reproducibility is in scope; do not report as product runtime. |
| Customer overlays / external infrastructure | Customer deployment configuration | Not centrally enumerated | Explicitly scope out or collect deployment-specific manifests during onboarding; never infer completeness from the reference Compose file. |

## Retention and assurance limitations

The current workflow uploads temporary GitHub Actions artifacts and attaches evidence to GitHub Releases. Temporary artifact retention is 30 days for the current release evidence paths; a GitHub Release attachment is useful distribution evidence but is not, by itself, a governed immutable archive with an accountable retention owner.

Before closing enterprise issue #96, define:

- a durable, access-controlled archive location and retention period;
- an accountable operational owner and restore/retrieval procedure;
- whether release evidence is copied to the archive automatically and verified by digest;
- explicit treatment of customer-specific overlays and non-reference deployment artifacts.

This inventory is a manifest-based coverage map. It does not assert that customer environments match the reference deployment, that all optional extras are currently shipped, or that any scanned component is vulnerability-free.
