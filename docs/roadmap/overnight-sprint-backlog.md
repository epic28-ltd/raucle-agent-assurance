# Overnight Sprint Backlog — Raucle Agent Assurance (5 Nov, 10x roadmap wave)

Source: Perplexity deep-research roadmap (attachments/10x Roadmap for Raucle Agent Assurance.md).
Validation: all four load-bearing external sources verified real this evening
(Agent Assure acblabs/agent-assure + claim-boundary docs; CAGE-1 arXiv:2607.03510
with Prebind Assurance as core concept; OpenAgentSafety arXiv:2507.06134, ICLR 2026,
MIT-licensed; AGENTSAFE arXiv:2512.03180, IBM-authored). Claims marked [V] = verified.
No unverifiable claims carried into this backlog.

Adaptation notes (validated against the assurance repo's actual state):
- Much of Sprint 1's raw material already exists: ops/audit-pack/pack.py (pack
  builder), tools/verifier/verify_pack.py (offline verifier with tamper classes),
  chain_graph, evidence_plane + replay (honest mismatch paths), the endpoint sweep.
  Build the Assurance Packet ON these, never beside them.
- The Red findings corpus (~/Projects/raucle-agent-red/corpora) and the receipts in
  the board's demo_data provide real fixtures for deterministic tests.
- Overlap guard: the 8-week sprint's Top-8 (chain reconstruction graph, Red
  regression baseline, canary scoring) live in OSS raucle; this backlog adds only
  what is NOT there. No duplication with the chain-graph work.
- Compliance-honest tone, British English, no em dashes, textContent-only UI,
  no fabricated verdicts, fail-visible — repo invariants apply to every item.

Working agreements (all items):
- PR flow: branch from main, PR into main, CI must be green. Orchestrator merges
  after review pass. Small committed chunks. pytest + ruff green per chunk.
- Every artifact deterministic and offline-verifiable from committed fixtures.
- Each finished item states: what a LASR auditor can now claim because it exists.

## Backlog (ordered, sized 45-90 min)

### OV-1 Agent Assurance Packet generator [P1, sprint 1 core]
- New module services/assurance_packet/: packet schema (versioned
  agent_assurance_packet.json): agent identity, capability chain, policy-proof
  refs, receipt-chain summary, gate-coverage indicators (admitted/held/refused
  counts from receipts), governance mapping slots (DORA, EU AI Act, ISO 42001,
  SOC 2, NIST AI RMF, OWASP LLM v1 crosswalk ids), risk annotations.
- Generator reuses pack.py primitives; deterministic output (stable field order,
  reproducible sha256 across runs on the same fixture chain).
- CLI: rauckle-assurance-packet (script entry) producing packet json + a
  textContent-only HTML summary.
- Tests: fixture receipt chain -> packet with golden sha256; tampered chain ->
  fail-visible error.

### OV-2 Assurance Packet REST endpoint
- POST /assurance/packet (and GET /assurance/summary) on the investigation-ui
  app or a new small service inside the repo, per endpoint-sweep patterns
  (4xx documented, honest-mismatch responses).
- Tests: extend the endpoint sweep suite.

### OV-3 Offline re-validation of a packet
- verify_pack extension: given a packet + published registry + policy proofs, an
  independent recheck reproduces the packet's verdict. Failure modes: swapped
  receipt, stale registry, missing proof -> explicit, non-silent.
- This is the 'prove it to my auditor' claim made executable for the PACKET.

### OV-4 Governance profiles + crosswalk data
- profiles.yaml: basic (sandboxed/low-consequence) vs regulated (financial/
  services) declaring REQUIRED control coverage and outcome semantics
  (fail vs warn).
- crosswalk.json: existing DORA/EU AI Act/ISO 42001/SOC 2/NCSC/CAF mappings
  extended with NIST AI RMF and OWASP LLM Top 10 rows; every row cites the
  raucle evidence field that satisfies it; UNSUPPORTED rows honest.
- Validator: packet vs profile -> PASS/PARTIAL/FAIL with machine-readable diff.

### OV-5 CI gate action
- GitHub composite action + reusable workflow: given an assurance packet and a
  governance profile, emit pass/fail/warn with a printed summary. Local-first:
  the script works with plain git + python, no paid deps.
- Fixture CI runs: green packet, missing coverage (fails), partial (warns).

### OV-6 Role-based docs
- docs/assurance/roles/leaders.md, architects.md, engineers.md ( LASR-facing
  language, no marketing inflation), plus a docs-alignment check script
  (roles reference only existing commands/artefacts).

### OV-7 Agent Process Expectations schema (Phase 2 start)
- expectations.yaml schema: per-case expected outcome, required evidence links,
  human-review routes, provider/tool/privacy boundaries, usage budgets,
  streaming-integrity invariants. Validator with precise error messages.

### OV-8 AgentRunRecord schema + fixture generator
- agent_run_record schema privacy-filtered: receipts, capability refs, policy
  proof ids, governance events, usage metrics. Fixture generation from the
  sovereign demonstrator's committed demo data (real receipt chain), no secrets.

### OV-9 Release compiler: compare + classify
- compile CLI: expectations + candidate RunSet vs baseline -> classification:
  new_failure / persistent_failure / preserved_controls / improved. The
  comparison output feeds the assurance packet as a release section.

### OV-10 Controls-efficacy mutation catalog (first cut)
- Mutation catalog v0: evidence-link removal, review-route bypass, boundary
  widening, replay duplicate. Kill-ratio computation per detector with bounded
  claims (explicit counts). Synthetic campaigns with known outcomes -> tests.

### OV-11 Scenario taxonomy + mapping (Phase 3 start)
- taxonomy.json: OpenAgentSafety 8 risk categories + CAGE-1 12 dimensions [V],
  each mapped to: the raucle primitive that evidences it (receipt kind, red
  rule id, expectation field) and its honest coverage status today.

### OV-12 Prebind Assurance indicators
- prebind module deriving per-receipt lifecycle states (admitted, held,
  narrowed=attenuated, refused, escalated, quarantined, no-bind) from existing
  gate receipts + red results; indicator set + counters in the packet.

### OV-13 Independent Assurance Agent scaffold (Phase 4 start)
- Reference implementation: a verifier agent that consumes packet + run records
  and produces an independent review opinion, structurally isolated (separate
  process entry, no builder context), documented with the AAS pattern mapping.

### OV-14 Improvement review (orchestrator)
- After the loop: what did the roadmap miss, what got easier because of OV-1..13,
  what is next-highest leverage. Feed back into the backlog as OV-15+.

## Non-goals tonight
- Dashboard UI expansion (Sprint 11) beyond existing board cards — keep UI churn
  minimal until the packet format stabilises through review.
- GRC platform connectors (Sprint 13): formats only, no vendor integrations.
- Anything touching OSS raucle main (that is a morning-review lane).

## Overnight outcome (final, 12h check-in)

Checked 5 Nov 2026, ~12 hours in, updated at end of wave 5. All numbers below
read live from `gh pr list --state merged`, `gh pr view` and git on
`epic28-ltd/raucle-agent-assurance` (and the raucle repo where cited); nothing
inferred.

### Final tallies

- 25 PRs merged overnight on the assurance repo (#26-#53 except closes),
  2 closed as superseded (#31, #39), 1 still open by design (#41, OV-9
  follow-ups, CI green, ready for morning review). Every merge passed CI and
  the SonarCloud quality gate.
- Bug-hunt round 1: 11 findings across 4 repos in total. Fixes landed via PRs
  #48 and #49 here and raucle#183 (projection + passport CLI crash-class
  fixes, merged). Cross-repo finding tallies live in the bug-hunt lane's
  tracker (raucle, agent-assurance, cloud, red).
- Assurance Sonar sweep: standing accepted-findings set driven down from 26
  toward the agreed target of 2. Round shipped #50-#53 (single-assert test
  discipline, prebind helper extraction, per-path S8707 acceptance in #52,
  residual S3776/S5778 hoists). The accepted set now lives in
  docs/spikes/SONAR-ACCEPTANCE.md with per-path rationales; final residual
  count reconciliation is morning work if the Sonar gate flags anything new.

### Round-2 improvement review items (OV-15..23 disposition)

Delivered tonight:

- OV-20 — done: #45 merged; the IAA consumes the revalidation report and
  cites REPRODUCED/MISMATCH, so its opinion is evidence-backed.
- OV-18 — done: improvement-review round 1 items that fed the sweep landed
  through #50-#53 (no open code work remains from that list).
- OV-22 — merged: #44 (optional ML-DSA-65 packet signature) with trust-model
  follow-up in #46 (OV-24).

Morning-review lane (landed in raucle, not the assurance repo; do not count
as delivered here):

- raucle#182 (open): agent-passport export from audit packs (OV-23, round-trip
  verified) plus chain-graph linkage (OV-21). When it merges, mark both items
  morning-review-complete.
- #41 OV-9 follow-ups (open here): determinism test, --output error path,
  tool-scope docstring for the release compiler.
- Trust-model notes from ov24 trust-model work landed through #46; the parked
  ov24-trust-model-notes branch remains unmerged and is not counted.

### Honest limits — what tonight did NOT deliver

Roadmap phases 2-4 are scaffolds, not systems. Still open from the roadmap:

- Scenario banks: OV-10's mutation catalog v0 and the OV-11 taxonomy exist,
  but the roadmap's per-category scenario banks (OpenAgentSafety 8 risk
  categories exercised end-to-end against real fixtures) are not built.
- GRC connectors: non-goal tonight, unchanged. Crosswalk/profiles are data
  and format only; no vendor integrations exist.
- Dashboards expansion: the board cards are as they were this morning; UI
  expansion deliberately held until the packet format stabilises through
  review.
- Phase 2/3/4 items OV-7 through OV-13 are first cuts: schemas, compilers and
  the IAA scaffold work but none has been exercised against a full release
  cycle with a real candidate RunSet.

### Honest LASR statement

Tonight a LASR auditor can credibly see, for the first time in one place, the
basic machinery an independent reviewer needs: an assurance packet generated
deterministically from committed receipt chains, re-derivable offline by a
second party, expressed against governance profiles and a scenario taxonomy,
signed optionally post-quantum, and reviewed by a structurally isolated
independent agent that cites whether the verdict was reproduced. What we have
not done is claim this constitutes an operating assurance regime: the packet
format has been exercised only on demonstration fixtures, not on a real
release; the independent agent's review is structurally sound but unexercised
as a workflow; and none of the roadmap's scenario banks, GRC integrations or
expanded dashboards exist. The 11 bug-hunt findings and the Sonar sweep
reduced the obvious defects and standing debt, which raises our confidence in
the fixtures themselves, but confidence in machinery is not evidence of
conformance, and no statement above should be read as conformance evidence
for any production agent run.

Backlog status after the run: OV-1 through OV-14 and the round-2 items
delivered code or dispositioned; phase 2-4 items remain scaffolds as noted
above; the open items are tracked in this section only.

All figures verified 5 Nov 2026, end of wave 5, against live `gh pr` state:
merges #45-#53, open #41 and raucle#182, and the SonarCloud gates on each
listed PR.
