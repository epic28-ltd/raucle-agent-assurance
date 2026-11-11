# Licensing

raucle-agent-assurance is open source under Apache-2.0, and it stays that
way. That is a permanent decision about this repository, not a launch
posture.

The commercial surface of the Raucle Agent Assurance product line is a
separate Enterprise Edition, built closed from the start in a private
repository (epic28-ltd/raucle-agent-assurance-ee). Enterprise capabilities
(fleet operator tooling, multi-tenant hosted components, commercial
connectors) are not developed here and are not harvested out of here later.
When a capability belongs in the Enterprise Edition, it is built there from
day one.

What this means, plainly:

- Everything in this repository is Apache-2.0. Use it, modify it,
  self-host it, build products on it.
- Nothing published here will be relicensed. There is no plan, now or
  later, to move this repository or any part of it to a restrictive or
  source-available licence.
- The packet format, the offline verifier, the crosswalk and the
  trace-correlation companion are open permanently. Evidence has to be
  verifiable by parties with no relationship to us; a verification layer
  that could go closed would contradict the product's own thesis.
- The Enterprise Edition is closed source and is never described as open
  source.

## Contributions

Contributions are made under the DCO (`git commit -s`); see CONTRIBUTING.md.
Because this repository will never be relicensed, a CLA is not required.

## Pack definitions, stated deliberately

The compliance pack definitions stay Apache-2.0 on purpose: auditors and
customers can copy the crosswalk content. The value this project keeps is
not the content; it is freshness, third-party reviewer engagement and
signed attestation binding the packs to live evidence.

## History note

On 11 November 2026 this repository briefly adopted a two-licence model
(Apache-2.0 audit path, FSL-1.1-ALv2 engine directories) in PRs #72-74. It
was reverted the same day by owner decision, before any FSL-covered release
was tagged: no release, tag or conversion-ledger entry was ever made under
FSL terms. The decision record is
docs/adr/0006-licensing-open-core-ee.md.

Tree states inside that one-day window carry FSL notices. Those historical
snapshots are the most restrictive states in this repository's history and
there is no reason to rely on them: the identical code is available under
Apache-2.0 at the revert commit and at HEAD. The repository's history
before and after the window is Apache-2.0 throughout.

Commercial-licence contact: `contact@epic28.com`.
