# ADR 0006: Licensing is open core, Apache-2.0 permanent, closed Enterprise Edition

Status: Accepted (owner decision, 11 November 2026; supersedes the same-day
two-licence split shipped in PRs #72-74)
Date: 2026-11-11
Deciders: EPIC28 / Craig (owner)

## Context

This repository briefly adopted a two-licence model on 11 November 2026: an
Apache-2.0 audit path and FSL-1.1-ALv2 engine directories, with a
CI-enforced header mapping and import-direction check (PRs #72-74). The
protective value of that split was thin: every commit published before the
boundary was already Apache-2.0 and forkable, so the split bound only
future commits to the engine directories while adding a "not fully open
source" posture to a product whose thesis is third-party verifiability.

## Decision

- This repository is Apache-2.0 permanently. No part of it will be
  relicensed to a restrictive or source-available licence.
- Enterprise capabilities (fleet operator tooling, multi-tenant hosted
  components, commercial connectors) are built closed from the start in
  the separate private repository epic28-ltd/raucle-agent-assurance-ee.
- Nothing Apache-published is harvested into the Enterprise Edition.
- Contributions are accepted under the DCO; no CLA is required because no
  relicensing will occur.
- Product copy: this repository is described as open source (Apache-2.0);
  the Enterprise Edition is never described as open source.

## Consequences

- The FSL machinery (per-directory notices, header mapping,
  import-direction check, conversion ledger) is reverted; the licence
  header CI check now enforces Apache-2.0 across the mapped tree.
- Commercial protection comes from building enterprise features closed
  from day one, not from licence exclusivity on published code.
- The 11 November FSL window stays in history unreleased: no release, tag
  or conversion entry was ever made under FSL terms. See the history note
  in LICENSING.md.
- Verification layers stay open permanently: an assurance product the
  auditor cannot inspect contradicts its own thesis (who audits the
  auditor).
