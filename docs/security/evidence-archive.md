# Durable evidence archive (release SBOM and vulnerability evidence)

**Status:** mechanism implemented and tested; release wiring live in CI; shipped-set vulnerability scan evidence-only, pending an owner decision
**Owner-decision status:** the accountable owner and the retention periods are PENDING owner decisions; they are deliberately not filled in by this work
**Governing issue:** assurance issue #96 (master backlog #90)
**Reviewed:** 2026-11-26

## What this is

`tools/evidence_archive/archive.py` is a deterministic generator that lays out an evidence archive from a declared inputs file: every SBOM, vulnerability report, component and provenance record is copied verbatim, its SHA-256 digest is recomputed (a declared digest that does not match the bytes fails the build with a named error), and the resulting manifest binds every artifact to immutable identities (source commit SHA, component digest, lockfile digest, requirements digest or resolved image digest).

The archive layout is:

```
<archive>/
  artifacts/<artifact-id>/<file>     the artifact bytes, byte-identical to their source
  MANIFEST.json                      canonical manifest (sorted keys, compact JSON, one trailing newline)
  MANIFEST.json.sha256               SHA-256 of MANIFEST.json
```

Commands:

```
python3 tools/evidence_archive/archive.py build --inputs inputs.json --base . --out <archive>
python3 tools/evidence_archive/archive.py verify <archive>
```

`build` refuses to write into an existing directory. `verify` recomputes the manifest digest and every artifact digest inside a built archive and exits non-zero on any mismatch. Both refuse with named errors (`MissingDigestError`, `DigestMismatchError`, `MissingBindingError`, `UnpinnedToolError`, `DigestFormatError`, `InvalidInputError`, `InputNotFoundError`, `DuplicateArtifactError`).

## Determinism and digest binding (proved by tests)

`tests/tools/test_evidence_archive.py` (22 tests) proves, against real files in temporary workspace directories:

- **Determinism:** the same inputs produce byte-identical `MANIFEST.json` and `MANIFEST.json.sha256` from two different base directories, and the manifest contains no running-environment paths. The generator never reads the wall clock: the only timestamp in the manifest is a caller-provided `recorded_utc`, carried verbatim or absent.
- **Digest binding correctness:** a tampered artifact (bytes do not hash to the declared digest) fails the build as `DigestMismatchError`, naming the artifact; a missing digest fails as `MissingDigestError`; an SBOM or vulnerability report with no immutable binding (no component, lockfile, requirements or image digest) fails as `MissingBindingError`; an image binding that is not a resolved `sha256:<64 hex>` digest fails as `DigestFormatError`.
- **Unpinned-tool refusal:** an SBOM or vulnerability report with no tool run, with an empty version, or with a placeholder version such as `latest`, `unpinned`, `main` or `nightly`, fails the build as `UnpinnedToolError`. The archive refuses an unpinned tool run by construction.
- A `verify` round trip passes on a built archive and catches post-build tampering with a named error.

## Pinned tooling

Every SBOM or vulnerability report entering an archive must record its pinned tools. The versions below are the pinned toolchain for SBOM and scan generation as of this document:

| Tool | Pin | Where it is pinned |
|---|---|---|
| Syft (SBOM) | `v1.57.2` | `syft-version` in every SBOM workflow (release-sbom, python-distribution-sbom, container-image-sbom, software-supply-chain, shipped-dependency-scan) |
| anchore/sbom-action | `f8bdd1d8ac5e901a77a92f111440fdb1b593736b` (v0.20.6) | SBOM workflows |
| actions/checkout | `11d5960a326750d5838078e36cf38b85af677262` (v4) | SBOM workflows |
| actions/setup-python | `a26af69be951a213d495a4c3e4e4022e16d87065` (v5) | SBOM workflows |
| actions/upload-artifact | `ea165f8d65b6e75b540449e92b4886f43607fa02` (v4.6.2) | SBOM workflows |
| actions/download-artifact | `d3f86a106a0bac45b974a628896c90dbdf5c8093` (v4.3.0) | release-sbom |
| uv (lockfile export) | `0.13.10` (PyPI) | shipped-dependency-scan workflow |
| pip-audit (vulnerability data) | `2.10.1` (PyPI) | shipped-dependency-scan workflow; the live CI gate in software-supply-chain installs the package from PyPI |
| evidence archive generator | `1.0.0` | recorded inside every `MANIFEST.json` as `generator` |

Advisory data is not version-pinned: pip-audit queries the live OSV/PyPI feeds at scan time. Every recorded audit report therefore names its scan disposition and must be read as point-in-time evidence; re-scanning can legitimately produce a different result.

## CI wiring in this change

- `release-sbom.yml` gains a `build-evidence-archive` job: it downloads the release source-SBOM evidence bundle, builds an archive whose SBOM is bound to the exact GitHub source-archive digest and provenance, verifies it, uploads it as an Actions artifact, and (on release events) the publish job attaches `MANIFEST.json`, `MANIFEST.json.sha256` and the signed-by-hash inputs file to the GitHub Release.
- `.github/workflows/shipped-dependency-scan.yml` (new) inventories and audits the shipped dependency sets of the two source services (`services/console`, `services/investigation-ui`) from their authoritative `uv.lock` files. Evidence produced per service: the exported exact locked requirement set (`uv export --locked --no-dev --all-extras`), its digest, a CycloneDX SBOM generated from that exported set (pinned Syft), and a live pip-audit JSON report. All four are bound to the lockfile digest, the source commit and the pinned tool versions in a provenance record.

## Shipped dependency coverage after this change

Covered, with evidence:

- Source release: CycloneDX SBOM bound to the exact GitHub source archive digest, now additionally bound into a verified archive manifest (release workflow).
- Six published Python distributions: wheel and sdist SBOMs digest-bound per file (pre-existing, unchanged).
- Seven reference Compose images: SBOMs from resolved immutable registry digests (pre-existing, unchanged). No reference image carries our lockfiles or pinned requirements; their identity is the resolved image digest, and the `python:3.12-alpine` evidence-index stub is stdlib-only.
- Two shipped source services (console, investigation-ui): NEW. SBOM and live vulnerability audit generated from the exact exported lock set (15 requirements each at scan time), digest-bound. The live audit result recorded 2026-11-26 with pip-audit 2.10.1: 12 advisory records covering 6 unique PYSEC advisory ids, all against `starlette==0.48.0` (transitive of the pinned `fastapi==0.118.3`). Fixed-in versions reported: 0.49.1, 1.0.1, 1.1.0, 1.3.0 and 1.3.1.

Not covered, named gaps (all explicitly not claimed this wave):

- **Shipped-set vulnerability gate is not blocking.** The shipped-set audit step is evidence-only: it runs `pip-audit -r <exported locked set> --strict` and retains the findings because wiring it as a blocking gate requires either a pinned-set upgrade that removes the `starlette==0.48.0` advisories, or an owner-approved exact-scope exception (at most 30 days, referencing a tracked issue). Neither decision is available to an agent; this stays an owner decision. Making the shipped-set scan blocking, and attaching its evidence to GitHub Releases (which would change the 14-file release SBOM count), is the named next slice.
- **Optional OTel and Raucle integration extras** are declared as empty placeholders and are not resolved by any lockfile. Until they are declared and locked, no archive claim may cover them. (Documented in the runtime dependency inventory since PR #115.)
- **Quality evaluator and correlation services** have no lockfiles and no shipping decision. If they become separately shipped deployment units, they need their own locked sets and scan entries before any coverage claim.
- **Customer-specific overlays and external infrastructure** are out of scope for this repository's archive until an owner decision defines whether customer deployment manifests are collected at onboarding; the reference Compose file is not evidence that customer environments match it.
- **Archive storage location, restore/retrieval procedure and retention** remain open owner decisions below.

## Live gate protection (proved by tests)

`tests/security/test_vulnerability_gate_isolation.py` (6 tests) guards the boundary between the synthetic PR #105 fixtures and the live gate:

- The live gate step in `software-supply-chain.yml` is exactly `pip-audit --local --strict --progress-spinner off`: it audits the installed environment, takes no exception input, no ignore flag, and no synthetic fixture path.
- The synthetic policy fixtures (`tests/security/test_vulnerability_policy.py`) and the live audit run as separate steps, in separate processes; the synthetic step is a pure pytest invocation that never shells out (no `subprocess`, `pip_audit` or `os` import, checked via AST).
- The synthetic evaluator holds no ambient exception state: exceptions pass through the explicit `exceptions` argument only, and a call that grants an exception leaves the next argument-free call still blocking (a leak would be visible).
- A sweep over every workflow file proves no workflow passes an exception, ignore-vuln or allowlist input to any `pip-audit` invocation, and no workflow feeds the synthetic evaluator into a scan; the only permitted reference is the standalone synthetic pytest step.
- The new shipped-dependency workflow's audit invocation carries `--strict` and no exception input, and the workflow documents its evidence-only classification in-file, with the classification guarded by a test so a future edit cannot silently turn the comment into suppression.

## Retention and ownership (PENDING OWNER DECISIONS)

Both of the following remain recorded decisions that have NOT been made. No person or period is filled in below, on purpose, because assigning them is outside agent authority. Until they are decided, the archive mechanism exists and is verified, but no governed retention can be claimed, and the durable archive location is "GitHub Release attachments plus Actions artifacts" only as a transitional statement of fact, not a governance decision.

**PENDING OWNER DECISION 1: accountable owner.** Required decision text:

> Name the accountable owner for the durable evidence archive (a named person or a standing role, with a delegate). Decision needed: (a) who owns the archive operationally, (b) who may add or remove evidence, (c) who verifies archive integrity after each release, (d) who is responsible for the restore/retrieval procedure. Until decided, the archive is ownerless and its retention cannot be operated.

**PENDING OWNER DECISION 2: retention period and procedure.** Required decision text:

> Set the retention period for release SBOM and vulnerability evidence and the restore/retrieval procedure. Decision needed: (a) how long each release's evidence must be retained (in months or years, and whether this differs between SBOMs, audit reports and provenance), (b) where the durable archive physically lives (GitHub Releases, a dedicated long-term storage target, or both), (c) the restore/retrieval procedure and who executes it, (d) whether evidence is copied to the archive automatically at release time and verified by digest. Current factual state: Actions artifacts are retained 30 days; GitHub Release attachments persist as long as the release exists; neither is, by itself, a governed immutable archive.

Recorded facts this work changes nothing on: the retention figures above are quoted from the current workflows (`retention-days: 30`) and the existing release attachment mechanics; they are measurements of the present state, not a policy.

## Honest limitations

- The archive generator and its gates are implemented and unit-tested; the release-archive job has not yet been observed on a real release event (it runs on pull_request events in CI and on every future release publish; the first real release will be its first live run at tag time).
- Whether the shipped-dependency-scan workflow passes on GitHub runners with the pinned toolchain has not been observed yet (it runs on this pull request; its Syft-on-exported-requirements step is exercised by CI for the first time there).
- Advisory data is point-in-time; the recorded starlette inventory is not a permanent statement that other advisories do not exist.
- This archive binds evidence to identities; it does not attest that any scanned component is vulnerability-free.
