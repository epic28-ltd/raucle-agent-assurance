# Durable evidence archive index

**Recorded:** 2026-11-27
**Owner decision source:** owner instruction, 2026-11-27 (retention policy: `RETENTION.md` in this directory)
**Governing design record:** `docs/security/evidence-archive.md` (mechanism and pinned tooling), merged as PR #124
**Relationship to CI:** this in-repository archive **supplements** the workflow artifacts and does **not** replace them. CI continues to publish SBOM and archive artifacts on its own runs (`release-sbom` on this repository, `sbom` on epic28-ltd/raucle); those artifacts carry GitHub's artifact retention (30 days on this repository's workflows, 90 days on the raucle SBOM workflow) and remain the primary CI distribution path.

This page is the durable, dated home for release evidence built by `tools/evidence_archive/archive.py` and committed under this directory. Every digest below comes from a live API read or from recomputing the downloaded artifact bytes at archive time; every committed archive is verified by the archive tooling, and `tests/tools/test_evidence_archive_home.py` guards that `MANIFEST.json`, this page and the retention policy stay mutually consistent.

## Inventory (latest first)

| Recorded (UTC) | Evidence | Repository | Archive directory | Release / tag | Source run |
|---|---|---|---|---|---|
| 2026-11-27 | Assurance source-release SBOM bundle | epic28-ltd/raucle-agent-assurance | `assurance-source-sbom-45986347562/` | `pull-request` (recorded by CI; branch of PR #128) | run 45986347562 (`release-sbom.yml`), finished 2026-11-27T10:57:23Z |
| 2026-11-24 | raucle release SBOM v0.23.9 | epic28-ltd/raucle | `raucle-release-sbom-v0239/` | `v0.23.9` | run 45466748310 (`sbom.yml`, tag push), finished 2026-11-24T19:07:29Z |

## raucle-release-sbom-v0239

- Source run: epic28-ltd/raucle run 45466748310 (workflow `sbom`), head commit `8d18c0d4b865a5ec12b7400d6113a9021411ec07`, the exact `v0.23.9` tag commit (tag object verified via the GitHub API on 2026-11-27). Artifact name in CI: `sbom-raucle-v0.23.9`.
- Build: committed on 2026-11-27 from the downloaded CI artifact plus the PyPI-published source distribution for raucle 0.23.9 (digest fetched from the PyPI JSON API and double-checked against the downloaded bytes).
- `recorded_utc` in the manifest: `2026-11-24T19:07:29Z` (the CI run's finished time, from `gh api`).
- SBOM: `artifacts/raucle-v0239-sbom/sbom-raucle-0.23.9.cdx.json`, sha256 `96080a4c78bd129ee476afe36cf3b48ab938618992c9417a2e0fa0dd13e8fe2b` (137,662 bytes). Tooling recorded inside the SBOM: cyclonedx-py 9.0.0, cyclonedx-python-lib 11.12.0; CycloneDX spec 1.6; 108 components; the SBOM names the raucle 0.23.9 component. Binding: component `raucle` version `0.23.9` sha256 `1657a7e56f01b2abe5b8bfe1aa369260896138a6f43bbf553b5dbbeab0977586`.
- Component: `artifacts/raucle-v0239-sdist/raucle-0.23.9.tar.gz`, sha256 `1657a7e56f01b2abe5b8bfe1aa369260896138a6f43bbf553b5dbbeab0977586` (3,808,167 bytes), the PyPI sdist for raucle 0.23.9.
- Build inputs used by the tooling: `provenance/raucle-release-sbom-v0239-inputs.json`.
- `MANIFEST.json` sha256: `6cee20b8a1ea503f691a05f6145e70d0d051a30a8796a97608986ce7f482c83b`.

## assurance-source-sbom-45986347562

- Source run: epic28-ltd/raucle-agent-assurance run 45986347562 (workflow `release-sbom`, event `pull_request`, branch `sonar/assurance-main-sweep3`, PR #128 lineage, finished 2026-11-27T10:57:23Z). CI checked out and scanned commit `d8b2fb5a8896866806538316959c737e6d755834` (recorded by CI in `artifacts/release-provenance/release-sbom-provenance.txt`; `pull_request` runs execute on the recorded merge commit, which is the commit the evidence binds to).
- Build: produced by the CI `build-evidence-archive` job with this repository's tooling, downloaded 2026-11-27 and committed verbatim. A local rebuild of the same committed input file byte-reproduced the CI bytes (manifest `b560ff6450ad4b31ac674566eba2e7f7b1652e669d4b9fc1ce3868432286875f`), so the determinism contract holds on real CI output, not only in tests.
- Artifacts in this archive: source SBOM `artifacts/source-sbom/sbom.cdx.json` (sha256 `e8e2498849842a3ca4aca1a43dfbbd74cf243b0181717e3f01fa696fafe25296`, 149,553 bytes; Syft 1.57.2 recorded inside the SBOM), source release component `artifacts/source-release-component/source-release.tar.gz` (sha256 `9e5d2bd04fc87d9fc938f710325b6b9259cbe81f5e726a72dc045caceda036e1`, 2,817,011 bytes), provenance record `artifacts/release-provenance/release-sbom-provenance.txt` (sha256 `6ec9bb6659f6c9ccc25459adf4968e6a69971b67952b5b76440d955ed5925a33`, 293 bytes).
- Build inputs used by CI: `provenance/assurance-source-sbom-45986347562-inputs.json`.
- `MANIFEST.json` sha256: `b560ff6450ad4b31ac674566eba2e7f7b1652e669d4b9fc1ce3868432286875f`.

## Keeping this archive honest

- Re-run verification at any time: `python3 tools/evidence_archive/archive.py verify docs/security/evidence/<archive-directory>`; a non-zero exit means the committed bytes and the manifest disagree.
- New entries are appended here with a dated row and a per-archive section; no committed entry is ever edited or deleted once built (see `RETENTION.md`).
- Numbers are read, not asserted: each row and digest in this page was produced while the underlying artifact was being downloaded or checked against the API that published it.
