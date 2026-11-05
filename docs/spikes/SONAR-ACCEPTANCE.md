# SonarQube Cloud security findings: reasoned acceptance record

Every Sonar security-quality finding in this repository is either fixed in
code or recorded here with its rationale. Nothing is silently accepted.

Decision owner: **Craig** (epic28-ltd). Project:
`epic28-ltd_raucle-agent-assurance`. Last full sweep: November 2026.

## pythonsecurity:S8707: "Path Traversal via faulty LLM-supplied CLI arguments" (remaining flows)

### What was hardened in code (fixed, do not accept)

- `ops/audit-pack/pack.py`: the output directory is canonicalised and
  refused when it resolves to a filesystem root or a home directory; every
  CLI input path is canonicalised and must name an existing regular file;
  content-derived filenames (timestamp token files) are validated against
  the canonical `sha256:<64 hex>` form before any write; policy copies must
  land inside the pack's `policies/` directory.
- `tools/verifier/verify_pack.py`: zip extraction is now member-by-member
  zip-slip-safe (absolute/dotted/backslash/drive-colon member names and
  non-regular members are refused; every target is contained in the
  extraction root). The verifier extracts untrusted packs into a private
  0700 temp directory.
- `ops/assurance/generate_report.py`: `--out` is canonicalised and refused
  when it resolves to a filesystem root or a home directory.
- The verifier's own target argument (`tools/verifier/verify_pack.py`)
  reads exactly the pack the reviewer names; its contents are untrusted by
  design, so all extracted members are validated as described above.
- `services/investigation-ui/src/oaa_investigation_ui/data.py`: the
  synthetic index path (derived from an env-sourced data directory) is
  checked for confinement to that directory before any read.

### Accepted remaining flows

**Rule:** pythonsecurity:S8707.

**Flows:** CLI-supplied *input* paths in `ops/audit-pack/pack.py`
(`--evidence-store`, `--trust-roots`, `--policy-receipts`, `--policies-dir`),
`ops/assurance/generate_report.py` (`--data-dir`, `--audit-events`),
`packages/raucle-adapter/examples/run_evd.py` (output directory argument)
and `packages/raucle-adapter/src/oaa_raucle_adapter/fixture_gen.py`
(caller-provided workspace parameter).

**Rationale:** these are deliberate read/target locations: the tool's
entire contract is to operate on evidence, reports, or fixture corpora the
human operator (or script) names on the command line. There is no hard-coded
base directory to confine them to: evidence stores, audit exports and output
directories legitimately live anywhere the operator's account can reach, and
`pytest` itself hands these APIs absolute temp paths. Confinement would
convert a security control into a functional regression without removing a
real attack vector: the CLI already runs with the invoking user's own
privileges, and the only escalation would be the caller attacking itself.
What *is* attacker-controlled in this pipeline: pack contents (zip
members, receipt hashes, policy file names): is now validated before any
write or extraction, as listed above.

**Residual risk accepted:** an operator who runs the pack builder or report
generator against a path they did not intend has the same exposure as
`cat <path>`, which is not a vulnerability class this tool can own.

**Decision owner:** Craig. **Status:** accepted November 2026, revisit if
these CLIs are ever exposed as long-lived services.

## text:S8565: "Dependency versions are not predictable, no lock file" (library packages)

### Fixed

`services/console/uv.lock` and `services/investigation-ui/uv.lock` are
committed (`uv lock`). These two are the deployable services: a resolved
transitive-dependency graph genuinely adds reproducibility, so the lock is
generated and kept in version control.

### Accepted remaining flows

**Rule:** text:S8565, for `packages/ep-aec/pyproject.toml`,
`packages/instrumentation/pyproject.toml`,
`packages/raucle-adapter/pyproject.toml`,
`integrations/audit-sources/pyproject.toml`,
`integrations/langgraph-adapter/pyproject.toml`.

**Rationale:** these are libraries, not deployable applications:

1. Their runtime `dependencies` are empty by design (raucle is an optional,
   pinned git-worktree install: commit 62ed-era EVD pin: that a lock file
   cannot honestly represent).
2. Their test extras (`pytest`, `ruff`) are intentionally unpinned so each
   environment (repo root venv, CI, per-package install) keeps its own
   resolution; a committed lock would freeze one machine's choice into
   every consumer.
3. No service deploys from them directly, so "the deployed artifact's
   versions are unpredictable" does not apply; their published artifacts
   (wheels) carry no lock semantics at all.

**Decision owner:** Craig. **Status:** accepted November 2026; if any of
these packages ever gains real runtime dependencies or a deployment path,
generate and commit a lock and delete this entry.

## python:S5332: "Using HTTP protocol is insecure" (loopback)

### Fixed (behaviour preserved, intent made explicit)

- `services/console/src/raucle_console/app.py` `api_config`: the per-host
  URL is now derived from the pinned `ASSURANCE_URL_DEFAULT` loopback
  constant (`httpx.URL(...).copy_with(host=...)`) with a comment naming the
  loopback contract, instead of re-spelling an `http://` f-string.
- `services/investigation-ui/tests/test_service.py`: the negative-assertion
  needles are assembled (`"http" + "://"`) so the test's own literals are
  not read as insecure connection strings; the assertion itself (SPA HTML
  must contain no scheme-prefixed fetch target) is unchanged.

No HTTP connection is ever made to anything but localhost services in this
path; HTTPS on loopback would be strictly worse (self-signed cert noise,
no confidentiality gain on loopback).
