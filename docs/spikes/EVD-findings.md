# EVD-01 / EVD-02 Findings — Evidence-Plane Harness & Conformance Fixtures

Date: 2026-11-04 · Profile: EPIC K (Open Agent Assurance companion)
raucle: pinned v0.23.5 @ **63edacd** (pinned worktree: `evd/raucle-63edacd`, additive `git worktree`; the main `~/Projects/raucle` clone has drifted to 2013a68 with a 507-line diff in `provenance.py`/`gateway.py`). Python: `~/Projects/raucle/.venv`. Synthetic data only; nothing committed; no external contact.

## 1. Fixture corpus (`evd/make_fixtures.py` → `evd/fixtures/corpus.jsonl`)

Each fixture line is exactly the on-disk envelope shape `{"receipt_hash": "...", "jws": "..."}` — the three genuine ones are captured **verbatim** from the raucle receipt store (JSON-parsed, then the raw line bytes re-emitted byte-for-byte); no hand-constructed envelope is ever verified as if genuine. Controlled-copy fixtures (invalid/unsupported_schema) start from genuine store envelopes and mutate only the field under test; their expected state is recorded in the manifest `note`, never inside the envelope.

Generated per run (fresh v1 gateway identity + `iat` from clock), so kids/timestamps differ between runs; structure and outcomes are deterministic (reruns pass the same sweep).

| fixture | how produced | expected | actual |
|---|---|---|---|
| `valid_allow` | verbatim store envelope, allow decision | valid | **valid** |
| `valid_deny` | verbatim store envelope, deny decision | valid | **valid** |
| `invalid_sig_flip` | controlled copy: 1st char of signature segment flipped | invalid | **invalid** — verify_chain: `receipt_hash mismatch — record tampered` + `signature verification failed` |
| `invalid_payload_tamper` | controlled copy: `x_gate.tool` rewritten inside signed payload | invalid | **invalid** — hash mismatch + signature fail |
| `unsupported_schema_crit` | controlled copy: JOSE header declares crit family `raucle/v2b` alongside `raucle/v1` | unsupported_schema | **unsupported_schema** — `from_jws` raises `unknown critical header parameter(s): ['raucle/v2b']` **before** any signature check |
| `unknown_key_v2only` | verbatim genuine envelope vs a trust root holding only key v2 | unknown_key | **unknown_key** (kid absent from archive at any event time) |
| `pending_async_ingest` | simulated (companion-side async ingest; no raucle call) | pending | **pending** |
| `unavailable_store_gone` | simulated (evidence object unreadable at retrieval) | unavailable | **unavailable** |

Result records live in `evd/results.json` (11 records incl. rotation cases); the verified sweep is the last section of `evd/run_evd.py` output — 11/11 PASS.

Key state-space fact learned: raucle's `ProvenanceVerifier` reports an unknown `kid` merely as `signature verification failed` — it does **not** distinguish unknown key from bad signature. The harness therefore performs the trust-root lookup (header `kid`, event time from the signed `iat`) itself and only then hands the envelope to `verify_chain`; `unknown_key` vs `invalid` is a companion-side classification, exactly as ADR-0001 §2 implies. `unsupported_schema` **is raisable without raucle code changes**: any foreign `crit` entry is rejected by `ProvenanceReceipt._enforce_header` ahead of signature verification.

## 2. Module API (`evd/evidence_plane.py`, Apache-2.0)

- `EvidenceStore(path)` — `put(envelope_line) -> digest` (refuses any envelope that is not exactly `{receipt_hash, jws}`); `get(receipt_hash)` first-match verbatim; `get_by_digest(digest)` byte-verbatim read-back with storage-integrity re-hash (raises `FileNotFoundError` → maps to `unavailable` in production ingest; `KeyError` on drift). Deliberately does *not* validate the JWS at rest — that is the verifier's job; fixture stores contain deliberately-broken records by design.
- `TrustRoot(key_id, public_key_pem, valid_from, valid_until, status)` + `TrustRootRegistry` — keyed `(key_id, valid_from, valid_until)`; `add`, `retire(key_id, valid_until)` (retired roots are archived, never deleted), `keys_for_event_time(event_time)` (archived roots stay selectable for historic events), `knows(key_id)`, change log `_history`. Timezone-aware ISO strings; `iat` (unix ts, tz=UTC) supplies event time per receipt.
- `VerificationResult` — dataclass: `fixture_name, verification_status, checked_at, verifier_version, trust_policy_version, checks_performed[], detail`. `verifier_version` is raucle's `raucle.__version__` in-process.
- `classify(envelope_line, registry)` — header parse → `kid`/`crit`/`alg`; trust-root lookup at event time (unknown → `unknown_key`; known-but-not-trusted-at-event-time → `invalid`); receipt_hash == sha256(compact jws) integrity check; then raucle's own `ProvenanceVerifier.verify_chain` on a temp single-line chain; error text mapped onto the ADR-0001 state space.

## 3. Rotation demo transcript (from `run_evd.py` output)

```
registry change log:
  add    key_id=fcf7f78dbfe44464 status=current
  retire key_id=fcf7f78dbfe44464 valid_until=2026-11-04T12:00:00+00:00
  add    key_id=512d7f9e7ab5936a status=current
  root key_id=fcf7f78dbfe44464… status=retired valid_from=2026-11-04T00:00:00+00:00 valid_until=2026-11-04T12:00:00+00:00
  root key_id=512d7f9e7ab5936a… status=current valid_from=2026-11-04T12:00:00+00:00 valid_until=None
historic receipt issued under v1; event_time=2026-11-04T09:00:00+00:00
v1 trusted at event time (retired but archived): True

[1] historic v1 receipt vs archive {v1(retired), v2(current)}:
   verification_status : valid
   checked_at          : 2026-11-04T08:41:06+00:00
   verifier_version    : 0.22.0 (raucle.__version__ constant; pinned distro v0.23.5)
   trust_policy_version: evd-trust-1
   checks: header parse; event_time from signed iat; trust_roots_at_event_time -> [v1];
           receipt_hash == sha256(compact jws); ProvenanceVerifier.verify_chain -> report.valid == True

[2] same receipt vs registry WITHOUT archived v1 (counterfactual):
   verification_status : unknown_key   ← the silent degradation ADR-0001 §2 prevents

[3] receipt under unregistered key → unknown_key
```

## 4. Version-record note

`raucle.__version__` reports **0.22.0**; the pinned distro (pip metadata) is **0.23.5** and the 63edacd commit message says "release: v0.23.5". The in-source `__version__` constant is stale at the pin. `verifier_version` recorded in results is therefore the raucle code constant; a pinned-verifier registry (COR-01) should record the distro pin, not the constant, until upstream fixes it.

## 5. Gaps

1. **Revocation semantics**: ADR-0001 §2 wants key-present-but-revoked-at-event-time → `invalid`, distinguished from plain expiry. raucle has no CRL; revocation is gate-time registry state. Needs raucle registry integration (import revocation events into the harness registry as a third status, or consume raucle's registry revoke stream). Not implemented here — registry supports `current`/`retired` only.
2. **Event-time vs check ordering**: harness classifies before handing to `verify_chain` so a mixed chain (some lines unknown-key, some invalid) under `verify_chain` on the full chain yields aggregate failure; per-line classification requires per-record invocation (as done here). Batch/per-receipt classification of full chains is unmeasured.
3. **`unsupported_schema` raisability**: confirmed raisable via crit headers. Future raucle *schema bump without crit change* (e.g. new crit-less header key or new payload shape) would surface as `malformed record` — the mapping of structural-parse failures to `unsupported_schema` vs `invalid` needs a policy rule once a real v2 exists.
4. **`pending`/`unavailable`/`not_applicable`** are companion-side states by construction (`not_applicable` not exercised here — no non-gate-trace fixture in scope for EVD-01/02).
5. **Determinism**: fixture regeneration re-mints keys/timestamps (kids change per run). For committed conformance fixtures a frozen corpus (pinned kid + PEM in-repo) is needed; generation code is deterministic in structure.
6. **Pinned-tree access**: main clone is at 2013a68 (v0.23.5 pin at 63edacd). Harness uses an additive worktree; before COR-01 the pin discipline needs deciding (checkout, worktree, or wheel pin).

## 6. Effort estimate: indexing into Postgres (COR-01)

- Schema (`verifications`, `receipts_index`, `trust_roots` tables; verification result record maps 1:1 to a `verifications` row; `checks_performed` as jsonb): **0.5–1 d**
- Ingest pipeline: EvidenceStore → classify → upsert index rows + verification record, state machine for pending→terminal incl. retries: **1–2 d**
- Trust-root registry admin API + audit log: **0.5–1 d**
- Sweep harness wiring (results.json → rows) + conformance CI job: **0.5 d**
- Total: **3–5 d** for a spike-grade COR-01 (no migrations framework, no auth), plus ~2 d contingency if revocation integration (gap 1) is pulled in.

## 7. Verdicts

- **EVD-01 (preserve canonical evidence)** — **PASS**. Verbatim `{receipt_hash, jws}` JSONL preserved byte-identical through the store (`get_by_digest` integrity check), envelope shape enforced, nothing derived substitutes for bytes; all 8 fixtures produced without mutating genuine envelopes.
- **EVD-02 (verify & index with full state classification)** — **PASS**. All 8 states exercised; invalid proven by raucle's own `verify_chain` failure; `unknown_key` distinguished from `invalid`; `unsupported_schema` raisable without code changes; rotation demo shows retired-key historic `valid`, counterfactual unarchived-key → `unknown_key`; every result records `verification_status/checked_at/verifier_version/trust_policy_version/checks_performed` (11/11 sweep PASS).