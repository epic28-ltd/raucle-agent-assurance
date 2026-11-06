# Red-Team Round 3 — Plan (attack-corpus prep lane)

Status: **PLAN — execution lane not started.** Round 3 red-teams the CURRENT
shipped suite once the last backlog PRs land. This document is the public-side
plan: attack-surface inventory, per-surface attack classes with the test that
would catch each, the containment-power abuse-case matrix, and honest
live-vs-offline limits. The executable attack corpus (fixtures, seeds, the
tests that consume them) lives in the private red repo
(epic28-ltd/raucle-agent-red, EPIC L conventions: red = private) — baseline
already opened as PR #15 (`feat/redteam-round3-baseline`): corpus manifest
`corpora/round3/attack_vectors.jsonl` (12 vectors, 10 classes) with offline
containment tests passing today as pins of shipped behaviour.

Closed-core line honoured: this file names attack CLASSES and the detecting
test; it does not carry payload tradecraft or step-by-step exploit detail —
that stays in red-repo `docs/round3-corpus.md`.

## 1. Attack-surface inventory (shipped suite today)

| # | Surface | Where it lives | Shipped invariants round 3 attacks |
| --- | --- | --- | --- |
| 1 | Containment CLI (hold/resume/status, scopes global/agent/chain) | raucle `raucle/containment.py` (origin/main, P4.A v0) | every halt/resume is a signed, offline-verifiable receipt; resume restores pre-hold bytes byte-exactly (sha256 both sides); hold serialises on flock; receipt-emission failure rolls the transition back; trace quarantine / lease suspension are **named v1 slots only** (not implemented — do not attack what does not exist) |
| 2 | Gate + receipts (policy load, delegated capability chains, revocations ledger) | raucle `raucle/gateway.py`, `capability.py`, policy machinery | fail-closed deny on missing/unknown policy; revocation leg shared with containment agent/chain scopes |
| 3 | Receipt forgery defence | raucle `raucle/verdicts.py` (`VerdictSigner`/`VerdictVerifier`), receipt streams | JWS envelope binds payload; offline verification against a published public half; stream contents are evidence, never authority |
| 4 | urlgate transparent proxy | raucle `raucle/urlgate.py` (EPIC O3) | gated traffic (chat/completions POSTs) consults the gate policy; non-gated loops pass through untouched; oversize-but-legitimate bodies accepted transparently; parity probes surface classification gaps explicitly |
| 5 | EQR gate inputs (evidence quality requirements) | raucle `raucle/eqr.py` (N6) | freshness/epoch integer arithmetic, source-class ladder, confidence floor as integers, fail-closed on unknown evidence |
| 6 | Nelson-14 delegation-receipt verifier | raucle `raucle/nelson14.py` | closed top-level body field set (`metadata` is the only extension point); all draft checks named, fail-closed |
| 7 | EP-AEC verifier (other implementers' chains) | raucle `raucle/epaec.py` + assurance `packages/ep-aec` (N4) | section-4 fail-closed algorithm: malformed/digest-mismatch/unregistered-type/evaluation-error all DENY |
| 8 | Bilateral outcomes (`x_bilateral`) | raucle `raucle/bilateral.py` (spec v1.2) | executor co-signature inside the receipt's signed payload over `output_hash`; missing/non-verifying co-signature is a named verification failure |
| 9 | SCITT transparency anchoring (chain-head non-equivocation) | raucle `raucle/transparency.py` (N2) | anchored head proves existence of that exact head; nothing more |
| 10 | Outcome verification (LANDED/REFUSED/UNCERTAIN) | raucle `raucle/outcome.py` | classification only, no enforcement claim |
| 11 | Judges / campaign machinery (P2.A2) | raucle-agent-red `red/judges.py`, `red/scheduler.py` | every verdict embeds ledger evidence pointers; standalone recomputation from pointers alone; unverifiable = fail-closed named failure |
| 12 | Durable ingest + portal (P2.B) | raucle-cloud `src/raucle_cloud/portal/`, chaos-child harness | oversize fail-closed named rejection; replayable dead letters surviving crash/restart; idempotent dedup merge |
| 13 | Instrumentation + collector scan quarantine (PRIV-01) | assurance `packages/instrumentation/`, `tests/security/` | protected mode stores zero planted seeds; `[REDACTED:class|len]` collar; suppression stamps carry class/attr/length, never values |
| 14 | Connectors (tool-side audit reconciliation) | raucle `raucle/connectors/` (entra/okta/github_audit) + Okta/Entra assurance integrations | evidence indexed from tool-side vantage; custody mapped per ADR-0004 |
| 15 | Assurance rules engine + correlation + EQR gate | assurance `services/rules/`, `services/correlation/` | index-plane only (canonical bytes never enter); SEC-009 corroborates only from receipt-exists correlation states |
| 16 | Fleet rollup (P2.C) | assurance `feat/p2c-fleet-rollup` (PR open at planning time) | honest rollup: fleet status computed over verified agent status, nothing inferred |

## 2. Attack classes per surface → catching test

| Attack class | Primary surfaces | The test/vector that catches it (corpus id) | Mode |
| --- | --- | --- | --- |
| Authority escalation (revoked subtree keeps working / re-mints through the same ledger) | 1, 2 | R3-01: scoped hold → re-register chain from the SAME delegation ledger → gate call must deny named; anything allowed during hold = finding | live-env |
| Receipt forgery (well-formed receipt signed by a foreign key adopted as authority) | 1, 3 | R3-02: foreign-key hold JWS appended to the containment receipt stream must fail offline `VerdictVerifier` verification, named | offline |
| Evidence substitution (verdict/chain material swapped post-signing) | 7, 11 | R3-03 + committed judges tamper row: swapping `state_after` recomputes to EVIDENCE_HASH_MISMATCH; EP-AEC digest-mismatch leg stays DENY | offline |
| Containment hold bypass (tamper the snapshot digest, then resume attacker bytes) | 1 | R3-04: resume with tampered `original_sha256` refuses named (digest mismatch), hold stays active | offline |
| Hold/activation race (silent interleave or silent no-op under lock contention) | 1, 2 | R3-11: double hold fails named (`already held`); resume without hold fails named (`not held`); flock serialisation pinned in the rauce containment tests | offline |
| Forge-then-halt (forge a receipt, base trust on stream contents, resume attacker policy) | 1, 3 | R3-12: composition of R3-02 + R3-04 + rollback leg — each leg fails named today; the chain must never silently merge | offline |
| Passthrough leaks (gated content tunnels through non-gated classifications) | 4, 13 | R3-05: method/path-variant tunnel bodies + oversize payloads against the live proxy; parity_gaps must stay 0; R3-08: secret placed in metadata passthrough paths — protected mode stores zero seeds (PRIV-01 harness template) | live-env |
| Queue loss (oversize, dead-letter loss on crash, dedup double-count) | 12 | R3-06: adversarial oversize/duplicate/replay sequences through `ingest_queue`; every envelope survives restart, counted exactly once | live-env |
| Judge non-recomputation (trust recorded verdict, skip recomputation) | 11 | R3-07: recorded PASS over recomputes-to-FAIL evidence → JUDGE_LEDGER_DIVERGENCE; `verify_verdict_against_ledger` additionally re-verifies the ledger chain and binds pointers to seq/entry_hash | offline |
| Quarantine bypass (secrets outside scanned spans; collar self-reflag) | 13 | R3-08: metadata-passthrough placements through the live instrumented path; collar must prevent self-reflag; violation stamps never carry values | live-env |
| Quarantine-of-the-quarantiner (attacker with write access to the containment state dir re-anchors the operator pubkey) | 1 | R3-09: pins the CURRENT trust anchor — see abuse-case matrix C-5; offline test asserts the shipped assumption, round 3 converts it into the hardening case | offline |
| SCITT equivocation (present an alternative chain head after anchoring) | 9 | R3-10: dual-head presentation must fail against the signed statement | live-env |

## 3. Abuse-case matrix — the containment power (who can halt what)

| id | abuse case | actor + preconditions | expected shipped response | round-3 vector |
| --- | --- | --- | --- | --- |
| C-0 | Legitimate halt | Operator (holder of the operator keypair) | Signed hold receipt; gate denies for the held scope; resume restores bytes exactly | raucle `tests/test_containment.py` (shipped) |
| C-1 | Forge a hold receipt and replay it | Anyone with write access to the receipt stream (no key needed) | Offline verification against the operator pubkey fails, named; stream is evidence, not authority | R3-02 / R3-12 |
| C-2 | Unreceipted halt (receipt emission fails mid-transition) | Operator + broken receipt stream | Transition rolled back — the halt does not take effect; a halt without its receipt is a bug, not a feature | raucle containment rollback test |
| C-3 | Resume to attacker-chosen bytes | Write access to the containment state file during a hold | Snapshot digest verification refuses the resume, named; hold stays active | R3-04 |
| C-4 | Scope escalation via mixed scopes (agent/chain hold vs global resume) | An attacker able to invoke the CLI with a different scope | State machine rejects: hold/resume must serialize on the same target state; cross-scope resume is named-refused | R3-11 legs + round-3 cross-scope case |
| C-5 | Quarantine-of-the-quarantiner: swap `containment-operator-pubkey.pem` | Write access to the containment state dir | **Shipped behaviour pins the pubkey file as the trust anchor — a state-dir writer re-anchors the quarantiner. This is DOCUMENTED LIMIT R3-L1, not defended behaviour.** Round 3 must (a) keep the pinning test as the honest statement, (b) evaluate out-of-band pinning (publish receipt hashes to the evidence plane / SCITT anchor) as the fix | R3-09 |
| C-6 | Race the halt (hold during concurrent policy activation) | Concurrent activation holding the file lock | flock serialisation; contender fails named, never interleaves or silently no-ops | R3-11 |
| C-7 | Double hold / blind resume | Any second caller during an active hold | Named errors (`already held` / `not held`), never silent no-ops | R3-11 |
| C-8 | Halt used as denial-of-service (legitimate global hold starves all agents indefinitely) | Operator or compromised operator key | In-scope v0 behaviour (an emergency stop is allowed to starve); round 3 documents the blast radius and requires the receipt trail to prove who/when/why — receipts contain actor + reason | documented, no vector |
| C-9 | Receipt-stream deletion (erase the receipt evidence of a halt) | Write access to the receipts JSONL | v0: stream is append-only by convention, not enforced — round 3 evaluates anchoring the receipt stream (SCITT/class 9 surface) so deletion becomes equivocation detectable | gap → round-3 hardening |
| C-10 | Trace quarantine (v1 named slot) attacked before it exists | — | Nothing to attack: quarantine is a named v1 slot, not implemented. Any red claim of "quarantine bypass" against v0 is a false claim | honesty gate |

## 4. Honest limits — live vs offline

**Offline-executable (deterministic, already in the red-repo PR as passing
containment tests):** containment receipt verification against forged keys,
snapshot-digest tamper, double-hold/blind-resume named errors, judge evidence
substitution + recorded-verdict divergence, corpus determinism. These need no
network, no gateway, no portal — they can run anywhere the round-3 raucle
worktree is pinned.

**Needs a live environment:**
- R3-01 authority escalation needs the live gate call loop (policy load →
  check → revocation refusal) over the pinned worktree.
- R3-05 urlgate passthrough needs the live transparent proxy and a real/stub
  upstream; parity_gaps only meaningful against real traffic shapes.
- R3-06 ingest queue loss needs the raucle-cloud portal stack + chaos-child
  crash/restart harness.
- R3-08 redaction bypass needs the instrumented trace path end-to-end
  (producer → collector → store), as PRIV-01's live harness does today.
- R3-10 SCITT equivocation needs a transparency service (live or a
  deterministic stub).
- The portal + collector surfaces additionally need the oaa stacks from the
  spike environment (3301/3302, 3401/3402) — coordinate teardown/rebuild with
  ops before the red round claims live coverage.

**Not attackable at all (do not claim vectors against):** trace quarantine and
lease suspension (named-but-unimplemented v1 containment slots), and the
fleet-rollup status surface (branch not yet merged at planning time —
re-inventory when it lands; attack class then is "rollup computed over
unverified/inferred status" rather than anything below).

**Sequencing note:** the pre-existing environment flake in
`test_gateway_http` (localhost connection resets, seen during this lane) must
be de-flaked or made retry-safe before round 3 runs live urlgate vectors, or
every live run will fight the harness.

## 5. Where things live

- Public plan (this file): `open-agent-assurance/tools/redteam/round3-plan.md`.
- Executable corpus + private tradecraft + limit register:
  `raucle-agent-red` PR #15 (`feat/redteam-round3-baseline` → dev),
  `docs/round3-corpus.md` inside.
- Round-3 raucle pin: read-only worktree at
  `~/Projects/oaa-round3/raucle-main` (origin/main at 7f4b3d3); overridable
  with `RAUCLE_ROUND3_WORKTREE`.
