# Licensing

Two licences apply across this repository, split by trust role. The rule is
simple: **everything an auditor needs to run the audit path is Apache-2.0;
the operational detection engine is source-available under the Functional
Source Licence.**

## Summary

| Surface | Licence | Why |
|---|---|---|
| Receipt and evidence formats, schemas, pack definitions | Apache-2.0 | Formats anyone may parse; the schema is the contract |
| `packages/instrumentation` (OTel ingest formats) | Apache-2.0 | Interoperable instrumentation must be inspectable |
| `packages/raucle-adapter` | Apache-2.0 | Bridge into the Apache-2.0 raucle gate |
| `packages/ep-aec` | Apache-2.0 | Implements the published verifier spec |
| `services/assurance_packet` | Apache-2.0 | Deterministic packet builder; the evidence artefact an auditor holds |
| `services/independent-assurance` | Apache-2.0 | The auditor-runnable checker; the who-audits-the-auditor guarantee |
| `docs/spec`, `docs/adr`, `schemas/` | Apache-2.0 | Public specification record |
| `services/correlation` (trace correlation and coverage engine) | FSL-1.1-ALv2 | Operational detection surface; converts to Apache-2.0 after two years |
| `services/prebind`, `services/rules`, `services/quality` | FSL-1.1-ALv2 | Engine and operating surface |
| `services/console`, `services/investigation-ui`, `services/evidence-index` | FSL-1.1-ALv2 | Operator and fleet surfaces |

Read `LICENSE-FSL.md` for the full Functional Source Licence text: standard
FSL terms, use, modification and self-hosting granted, competing products
excluded, and every release converts to Apache-2.0 two years after its
release date. The root `LICENSE` stays Apache-2.0; directories not carrying
their own notice fall under the Apache-2.0 root.

## Boundary and history

Commits up to and including `804e50f862005e94b6cf28a81b8a114ed0aad868` (12 Nov boundary, the Apache-2.0 era) remain Apache-2.0 and may be forked. The licence change applies from the `feat/licensing-fsl-engine`
boundary commit onward. A solicited solicitor review of the boundary commit
is pending; until that review returns, treat this file as stated intent.
Contributions after the boundary are made under a DCO **plus a signed CLA**;
no outside PR is merged under the DCO alone, because DCO alone does not
carry relicence rights. Until the CLA bot is wired in, every outside PR is
left unmerged. Note for the solicitor review: much of this code is AI-assisted
(some release notes are marked as generated with Claude Code); authorship and
ownership implications should be read at sign-off.

## Copy discipline

Product copy must say: the core and verifier are open source (Apache-2.0),
the assurance engine is source-available (FSL-1.1-ALv2, converting to
Apache-2.0 after two years). Do not describe the whole suite as open source.

## Release conversion ledger

Every FSL-covered release converts to Apache-2.0 two years after it is made
available. The first FSL-boundary release is gated on the solicitor review;
until then no FSL release is tagged. The ledger grows from that point:

| Version | Release date | Converted to Apache-2.0 on |
|---|---|---|
| (first FSL release pending solicitor review) | | |

## What the FSL allows (FAQ)

- A bank running the engine in production for its own agents: **permitted**.
- A consultancy running the engine for itself and its own clients'
  operations: **permitted** (professional-services use of the Software,
  not a competing product).
- A managed-service provider hosting or reselling the engine for other
  organisations: that is a **competing use**; contact us for a commercial
  licence.
- Redistributing modified copies with attribution per the licence terms:
  **permitted**, including for internal use.

Commercial-licence contact: `contact@epic28.com`.

Import direction: the Apache-2 audit path never imports FSL-surface code; a CI check enforces it.

## Pack definitions, stated deliberately

The compliance pack definitions stay Apache-2.0 on purpose: auditors and
customers can copy the crosswalk content. The value this project keeps is
not the content; it is freshness, third-party reviewer engagement and
signed attestation binding the packs to live evidence.
