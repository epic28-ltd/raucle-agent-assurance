# Evidence archive retention policy

**Decision recorded:** 2026-11-27, on the owner's instruction (Craig Allan-McWilliams, epic28-ltd). This resolves the two pending owner decisions recorded in `docs/security/evidence-archive.md` (`accountable owner`, `retention period and procedure`): the accountable owner is the epic28-ltd assurance owner (Craig Allan-McWilliams), and the durable archive is owned by the raucle-agent-assurance repository itself.

The durable archive **supplements the CI artifacts and does not replace them**: the `release-sbom`, `sbom`, `software-supply-chain` and related workflows keep producing and uploading their artifacts on their usual runs, with GitHub's default retention. This in-repository copy is the retention-owned home the CI artifacts are folded back into.

## Rules

1. **Minimum retention: 12 months** from each entry's recorded date. No committed evidence is deleted or pruned before 12 months have passed. Entries are not deleted at the 12-month mark either; 12 months is a floor, not a service life.
2. **Monthly review.** Once a month, the owner (or a lane acting under the owner's instruction) checks: (a) every committed archive in this directory still verifies with `tools/evidence_archive/archive.py verify`; (b) `ARCHIVE-INDEX.md` still matches the committed manifests (the guard tests enforce this); (c) every release published in the month has a corresponding archive entry, and adds any missing one; (d) the review log below is appended with a dated line. The review is a check, not a rewrite: entries are additive.
3. **Keep indefinitely (immutable evidence).** SBOM and scan artifacts, `MANIFEST.json`, `MANIFEST.json.sha256`, provenance records and the build input files are commit-once content: they are never edited in place and never re-issued under the same name. Any correction is a new dated entry plus an index correction, in the same spirit as the dated-correction convention used for issue comments.
4. **Re-derive rather than accumulate (point-in-time evidence).** Advisory and vulnerability audit results (for example pip-audit reports, whose advisory feeds are live and not version-pinned) are point-in-time statements. They may be dropped at the monthly review once they are 12 months old, provided the review records re-derivation in the log; SBOMs, manifests and digest sidecars are never in this class.
5. **Retrieval and restore.** The durable home is the repository tree, so retrieval is a git read of a retained commit, and `archive.py verify` re-attests integrity against the digest sidecar at retrieval time. No external storage copy is required for a restore; if one is added later, it is recorded here before it is relied on.

## Review log

- 2026-11-27: archive home created with two committed archives (`raucle-release-sbom-v0239`, `assurance-source-sbom-45986347562`); both verified with the archive tooling in the same change. First monthly review due December 2026.
