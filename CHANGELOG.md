# Changelog

All notable changes to Open Agent Assurance are documented here.
Format based on Keep a Changelog; versioning will be semver from 0.1.0.

## Unreleased

Current repository state: alpha, in progress. Everything below is imported
from completed 4-Nov-2026 spike work (EPIC K, Open Agent Assurance companion).

### Added

- Project layout, ADRs (0001–0003) and threat model v0 (imported from the
  ARCH-01 planning directory).
- Spike findings under `docs/spikes/`: DISC-02 correlation spike, EVD-01/02
  evidence-plane spike, OBS-01/02 observability vertical slice, backend
  capability matrix, trace-semantics workstream notes.
- `packages/raucle-adapter`: evidence-plane core module (`EvidenceStore`
  byte-verbatim JSONL store with sha256 integrity; `TrustRootRegistry` with
  archived-key retire semantics and event-time selection; `classify()` mapping
  raucle verifier outcomes to the ADR-0001 state space), adapted from the EVD
  spike harness. raucle is an optional pinned dependency (v0.23.5, git
  63edacd; verifier_version keyed on the distro pin because raucle's
  `__version__` is stale), imported lazily.
- Conformance fixture corpus (`tests/conformance/corpus.jsonl`, generated via
  raucle's real signing path) and pytest suites: raucle-free evidence-plane
  unit tests plus a signature-verification sweep that SKIPs when raucle is
  unavailable.
- Example scripts: deterministic fixture generator (`fixture_gen.py` CLI) and
  the full EVD harness (`examples/run_evd.py`).
- OBS-01 reference agent and probe scripts (`examples/reference-agent/`) with
  round-trip fidelity, score attachment and OTLP-outage reports.
- Langfuse v4.74.0 self-host compose stack (`deploy/compose/`).
- Repo scaffolding: Apache-2.0 LICENSE, NOTICE, SECURITY.md, CONTRIBUTING.md,
  README, ruff/pytest configuration, GitHub Actions workflow (ruff + pytest,
  Python 3.11/3.12; local file only — nothing pushed).

### Known gaps / TODOs

- P1.7a/P1.7b shipped: offline auditor export pack (self-contained, pinned
  key snapshot) and standalone verifier CLI; verifier hardened against
  damaged packs with named RED verdicts.
- P1.7c shipped: one-page auditor quickstart (`docs/auditor-quickstart.md`),
  claim-sheet renderer CLI (`scripts/render_claim_sheet.py`) that re-renders
  the generated claim sheet through the same honest-report generator with the
  no-claim guard re-checked before print, and a rendered demo claim sheet
  (`docs/demo/auditor-claims-demo.md`). Honest gap: no independent human
  dry run of the quickstart yet; automated offline-path test stands in.
- Remote hosting decision for the repository; no remote/push exists yet.
- Name and trademark check for "Open Agent Assurance" before public branding.
- CI on a hosted runner pending the remote decision.
- Evidence-sink failure behaviour needs a named risk-owner decision.
- Trust-root registry schema is implemented only as far as the spike harness.