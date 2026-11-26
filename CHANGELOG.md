# Changelog

All notable changes to Open Agent Assurance are documented here.
Format based on Keep a Changelog; versioning will be semver from 0.1.0.

## Unreleased

### 2026-11-26: tracestate grammar conformance and checker fix round

- Post-merge checker minors closed for the OpenTelemetry slice: the
  tracestate value grammar now matches the W3C ABNF exactly (comma was
  previously permitted in a value, letting the formatter emit a header
  its own parser drops whole; the final value character is now non-blank),
  and multi-tenant keys enforce the spec sub-lengths with digit-initial
  tenant ids accepted (`tests/otel/test_w3c_tracecontext.py` pins each
  shape; the formatter rejects what it cannot emit).
- Empty and whitespace-only tracestate list members are skipped instead of
  invalidating the whole header, as the W3C list grammar requires (some
  vendors inject whitespace after commas); genuinely malformed members
  still drop the whole header.
- House punctuation and claim precision: em dashes removed from the
  issue-111 docstrings, and the propagation docs now state exactly what
  rides the gate event (a fully validated `traceparent`, a length-bounded
  raw `tracestate` re-validated at the sink before parenting).

### 2026-11-26: OpenTelemetry trace-context propagation and OTLP export path

- W3C Trace Context now enters through the LangGraph adapter's callback
  seam: a stdlib-only `w3c_trace_context_getter` validates `traceparent`
  and `tracestate` in request state (bounded, dropped whole when malformed,
  never raising, never influencing a decision) and adopts the header's
  trace id only when the runtime carried no correlation id of its own. The
  middleware forwards the validated headers onto the gate event; the
  adapter package still never imports OpenTelemetry.
- The instrumentation package gains the canonical pure-stdlib parser and
  formatter (`w3c_tracecontext`), a generic env-configured OTLP/HTTP export
  path (`otel_export`) that is disabled until `OAA_OTLP_ENDPOINT` is set
  (independent `OAA_OTEL_DISABLED` kill switch, https-only endpoints with
  loopback and opt-in rules), and `OtelGateSinks`, which turn gate events
  into `oaa.gate.decision` spans parented onto the caller's trace.
- Exporter failure is visible, not silent: bounded attempts with capped
  exponential backoff, explicit loss counters, and a post-recovery
  `oaa.telemetry.span_loss` marker span, replacing the stock OTLP
  exporter's silent drop on connection refused (ADR-0003 P3). The PRIV-01
  `RedactingSpanExporter` sits inside the retry loop, so every attempt and
  the marker are scrubbed before export; the gate sinks export metadata
  only and never raw prompts, tool arguments or gate exception text.
- Fail-independence is asserted, not assumed: decisions are identical with
  telemetry up, down or absent, and the signed `x_gate` trace id remains
  authoritative on the correlation plane (ADR-0007).

### 2026-11-25: SOC 2 TSC mapping v1

- Added a machine-readable mapping for all 33 Common Criteria and 18 additional Availability, Confidentiality, Processing Integrity and Privacy criteria (51 total). Existing CC7.1, CC7.2 and CC9.1 mappings retain their identifiers and governance-profile compatibility; all other criteria are explicitly UNSUPPORTED until suitable evidence exists.
- Added the SOC 2 evidence pack, compliance-index entry and tests for full criterion inventory, status parity, unsupported-gap reasons, GRC export coverage and claim boundaries. This is a technical evidence crosswalk only, not a SOC 2 report, audit opinion or compliance claim.

### 2026-11-18: pack-shelf test hardening (checker minors B6)

- The six compliance pack test files' status checks now parse the packs' own
  markdown table Status column and match it bidirectionally against the
  machine crosswalk (per pack: parsed id set equals the framework's crosswalk
  row set, each status uses the fixed SUPPORTED/PARTIAL/UNSUPPORTED
  vocabulary and equals the crosswalk status, and SUPPORTED rows cite their
  evidence field), so genuine status drift between pack markdown and
  crosswalk data now fails. Red evidence: a scratch-copy drift check with a
  single injected `SUPPORTED` -> `PARTIAL` flip was caught by the parser
  (`status drift: Art 12(1) logging pack=PARTIAL crosswalk=SUPPORTED`).
- The vendor-copy guard (`test_pack_copy_names_no_vendors`) now covers the
  shared compliance index (`docs/compliance/README.md`) as well as the pack
  doc for every pack, aligned on the ISO 42001 variant (previously only the
  ISO 42001 and, pack-doc-only, NIST AI RMF and HITRUST variants carried it).

### 2026-11-17: HITRUST AI Security Framework compliance pack v1

- Fifth enterprise checklist pack: a mapping of the evidence plane (gate
  receipts, receipt chain, custody coverage, red-run findings, packet
  revalidation) to the HITRUST CSF v11 AI-specific control topics, in four
  areas (AI system inventory and accountability, AI change management, AI
  data protection, AI incident response): 10 crosswalk rows (2 SUPPORTED,
  4 PARTIAL, 4 UNSUPPORTED), honest verdicts per the fixed vocabulary, row
  structure identical to the other packs.
- HITRUST is licence-restricted: the pack reproduces no control text, only
  descriptive topic ids and short titles, with an explicit numbering
  caveat that the topic structure follows the public AI assessment outlines
  and must be verified against the licensed CSF before buyer-facing use.
- Machine-readable rows in `ops/assurance-profiles/crosswalk.json` export
  through the existing `grc_evidence_graph/v1` export unchanged; consistency
  tests in `tests/assurance/test_hitrust_ai_pack.py` (load-path parity with
  the other packs, bidirectional pack/crosswalk checks, claim-language and
  vendor guards, no-text-reproduction guard, export coverage, index check).

### 2026-11-17: distribution-pin re-key raucle 0.23.6 + fixture regeneration

- Re-keyed `RAUCLE_DISTRIBUTION_PIN` from `raucle 0.23.5 (git 63edacd)` to
  `raucle 0.23.6 (git 645f5de)` (the v0.23.6 git tag in epic28-ltd/raucle),
  across the evidence plane, the LangGraph gate client, the EP-AEC native
  verifier profile digest, tests, examples and docs.
- Regenerated the conformance fixture corpus against the raucle 0.23.6 chain
  (receipt hashes/JWS in `tests/conformance/corpus.jsonl` re-issued; no other
  committed artifact asserts the old receipt digests).
- Pinned `raucle==0.23.6` in the SonarQube workflow install (was unpinned
  `>=0.23.5`), which was the root cause: 0.23.6 published to PyPI after
  main's last green run, tripping `DistributionPinDrift` x9 on the next run.
  Prerequisite for SonarQube green on all assurance PRs.

### 2026-11-12: hosted-surface auth (R2 slice 1)

- Hosted OIDC identity federation for the console + investigation UI
  (`oaa_hosted_auth`): org-IdP login end to end (discovery fail-closed at
  boot, PKCE S256, strict id_token verification, single-use state/nonce)
  matching the gateway admin-plane idiom (X3 slice 1), short-lived
  receipted bearer sessions (`oas_`, digest-only store, capped, TTL
  enforced, refresh live), OFF by default with a byte-identical legacy
  open mode when disabled.
- Route-level role ladder on both hosted surfaces: viewer / operator /
  security-admin with a permission matrix bound at registration
  (matrix-completeness test walks both apps in CI) and a default-deny
  net for unbound paths; fail-closed default view-only for unlisted and
  unknown-role identities; no-JS data pages refuse unauthenticated and
  insufficient-role visitors as an explicit HTML login-required page.
- Receipted role changes: security-admin-only grant/revoke with a
  required reason, receipted in a tamper-evident hashed ledger
  (chain-verified on load and boot; a truncated/edited ledger refuses
  boot), effective on the next request, replayed across boots after the
  env grant baseline.
- SPAs: one inline login hook per page (fetch-bearer interposition from
  sessionStorage, IdP-redirect capture into the callback exchange,
  config-probe redirect to `/api/oidc/login`).

### 2026-11-05 → 07: sprint wave (PRs #26–#65)

The 4-Nov spike imports below are followed by the merged sprint wave. Every
entry lists the PR that carried it.

### Added (sprint wave)

- OV-1 assurance packet generator (#28); OV-3 packet offline re-validation
  (#30); role-based assurance pages plus the OV-6 docs-alignment check (#29);
  OV-15 fence-aware docs-alignment parser (#42).
- Run records: privacy-filtered AgentRunRecord schema + fixture generator,
  OV-8 (#27); Agent Process Expectations schema + validator, OV-7 (#32);
  scenario taxonomy OV-11 (#34) and OV-26 scenario banks + offline harness
  CLI (#57).
- Prebind indicators OV-12/#35 and OV-16 round 2 (#43) — CAGE-1 lifecycle
  states derived from gate receipts, evidence-backed narrowed/no_bind
  counters; independent-verification controls OV-9 release compiler (#37)
  with determinism/--output follow-ups (#41).
- OV-10 controls-efficacy mutation catalog + campaign runner v0 (#40);
  OV-13 Independent Assurance Agent scaffold (#36); OV-20 IAA consumes
  revalidation reports and cites REPRODUCED/MISMATCH (#45).
- OV-22 optional ML-DSA-65 packet signature over the packet digest (#44) and
  PQ signature trust-model docs (#46).
- OV-27 GRC evidence-graph export `grc_evidence_graph/v1` (#56); N7 AIUC-1
  crosswalk rows + `workpapers/v1` verbatim-cited export (#58).
- OV-5 assurance-gate CI action + reusable workflow + fixture runs (#33);
  investigation-UI assurance packet over HTTP, OV-2 (#38).
- P2.C honest fleet rollup + fleet baseline status on one view (#59).

### Fixed (sprint wave)

- Bug-hunt round 1 (#49): evidence readers named-skip malformed lines
  (prebind, correlation, run-records, crosswalk, release compiler);
  round 2 (#60): named failures for malformed evidence-store lines and
  crosswalk rows.
- Policy receipt staging tolerates undecodable store entries (named skip,
  no pack crash) (#48); `revalidate_packet` CLI input-read canonicalisation
  (#55).

### Documentation (sprint wave)

- Overnight ledgers (#47, #54), validated 10x backlog (#26), red-team
  round-3 plan (#61), per-path S8707 acceptance notes (#52).

### Security (sprint wave)

- RED-031 round-3 remediation (#65) — see the Security section below (same
  change, merged in the wave). Sonar residual sweeps cleared all 23 open
  main-branch findings to 0 (#62) with follow-ups (#63, #64), and the
  wave-4 refactor/sonar lanes (#1–#5, plus #51, #53) were gated per-PR with
  0 open issues on new code.

Current repository state: alpha, in progress. The entries below are imported
from completed 4-Nov-2026 spike work (EPIC K, Open Agent Assurance companion).

### Added (2026-11-05 → 2026-11-07, PRs #3–#66)

- P2.C investigation-UI work: assurance packet over HTTP, honest fleet
  rollup + fleet baseline status, Independent Assurance Agent scaffold
  (#37, #38, #59).
- OV-26 scenario banks + offline harness CLI, OV-27 GRC evidence-graph
  export (`grc_evidence_graph/v1`), AIUC-1 crosswalk rows +
  workpapers/v1 export (#56, #57, #58).
- OV releases: prebind indicators round 2, controls-efficacy mutation
  catalog + campaign runner, release compiler, IAA consumes
  revalidation report, optional ML-DSA-65 packet signature, PQ
  signature trust-model docs, fence-aware docs-alignment parser
  (#36, #40–#46).
- Security / hardening: named `DistributionPinDrift` tripwire on the
  raucle distribution pin (#66), RED-031 — remove the blanket
  `oaa.metadata.*` redaction allowlist (#65), bug-hunt rounds 1–2
  with named failures for malformed evidence/crosswalk lines
  (#49, #60, #48, #55).

### Fixed (2026-11-05 → 2026-11-07)

- SonarCloud residual sweeps: main-branch findings cleared to 0 over
  three rounds (#50–#53, #62–#64).
- Documentation: red-team round-3 plan, per-path acceptance notes,
  overnight ledgers (#47, #52, #54, #61).

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
- P1.7V verification story: the second-laptop auditor role-play
  (`ops/audit-pack/second_laptop.py`, `scripts/second_laptop_roleplay.py`).
  It builds a fresh real pack, hands only the pack and `verify_pack.py` to a
  throwaway "second laptop" directory, proves the network namespace truly
  denies network before trusting it, verifies GREEN in that namespace,
  proves the deliberate-tamper RED path offline, re-renders the claim sheet
  through `scripts/render_claim_sheet.py` with the no-claim guard
  re-asserted, and signs the verified sheet with a fresh ephemeral Ed25519
  key held on the laptop. Where no denied namespace exists (macOS, rootless
  restrictions), the run completes and states plainly that network denial
  was not namespace-proven. Honest limits: same kernel, same machine, one
  directory; not a second device.
- Repo scaffolding: Apache-2.0 LICENSE, NOTICE, SECURITY.md, CONTRIBUTING.md,
  README, ruff/pytest configuration, GitHub Actions workflow (ruff + pytest,
  Python 3.11/3.12; local file only — nothing pushed).

### Security

- RED-031 (round-3 remediation): the blanket `oaa.metadata.*` redaction
  allowlist is REMOVED — metadata values now pass through the same
  SDK secret-scan/redact pipeline and the collector batch re-scan as any
  other value (config v2 ships `allowlist: []`; the only named passthrough
  is the EMPTY value). Metadata-planted secrets are redacted at the SDK
  and quarantined at the collector.

- SonarQube Cloud security sweep (Nov 2026): harden AUD-01 pack builder
  (`--out` canonicalisation/refusal, CLI input canonicalisation,
  content-derived filename validation, policy-copy containment), zip-slip-
  safe pack verification, investigation-UI data-dir confinement and finding
  id validation, loopback HTTP intent made explicit (console `api_config`),
  private-demo paths instead of publicly writable `/tmp` literals in
  fixtures and tests, and committed `uv.lock` files for the two deployable
  services. Accepted-remainder decisions (operator-chosen input paths,
  library packages without locks) are recorded in
  `docs/spikes/SONAR-ACCEPTANCE.md`.

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