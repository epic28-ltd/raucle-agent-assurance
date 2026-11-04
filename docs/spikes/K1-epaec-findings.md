# EPIC M K1 — EP-AEC Envelope Generator + Evaluator (findings)

Status: **implemented** — `oaa-ep-aec` package (`packages/ep-aec/src/oaa_epaec/`),
Apache-2.0. Suite green, ruff clean repo-wide, nothing committed.

## What was built

- `objects.py` — EP-AEC-v1 Action Object builder, JCS (RFC 8785)
  canonicaliser for the used subset, AEC assembly, fixed-limit requirement
  evaluator, EP-AEC-REPLAY-v1 record assembly.
- `generator.py` — AEC envelopes from a verbatim `{receipt_hash, jws}` JSONL
  evidence-store directory; raw JWS referenced, never embedded (unless
  `EpaecConfig(allow_embed_jws=True)`).

## Receipt → component mapping

| receipt field | AEC field |
|---|---|
| `receipt_hash` | `components[].evidence_digest == receipt_hash` |
| `jws` | referenced only; embedded solely on explicit opt-in |
| `payload.x_gate.tool` (fallback `operation`) | `action.tool` |
| `payload.x_gate.args` when present | `action.args_digest` = sha256 over JCS of args, `args_digest_basis="x_gate-args"` |
| (no `args` in receipts) | `action.args_digest` = sha256 over descriptive-salted receipt hash, `args_digest_basis="descriptive"` |
| `payload.x_gate.agent_id` | `action.principal` |
| `payload.x_gate.acting_for` / `approval_id` | `action.delegated_authority` (null when empty) |
| `payload.x_gate.trace_id` | `action.trace_id` |
| `decision == "allow"` | component TYPE (role label) `policy-permit` default, or custom family e.g. `rau-cle-gate-decision` via `EpaecConfig.component_type` |

Verification facts per component (replay record): evidence-plane classification
(`valid`→VERIFIED, else ACCEPTED), `verifier_version` = raucle distro pin
("raucle 0.23.5 (git 63edacd)"), `trust_policy_version` (evd-trust-1),
`checks_performed` checklist, freshness basis (receipt signed `iat` within
trust window at event time), trust snapshot digest over the sorted
`(key_id, valid_from, valid_until, status)` root set of
`evidence_plane.TrustRootRegistry`.

## EP-AEC-REPLAY-v1 record schema (as implemented)

```
{"@version":"EP-AEC-REPLAY-v1","aec_digest":"sha256:<hex>","verdict":..., 
 "reason_codes":[...],"requirement":"...","evaluated_at":iso,
 "evaluator_profile_digest":"EP-AEC-EVALUATOR-08-v1",
 "evaluator_limits":{"max_requirement_bytes":4096,"max_requirement_tokens":256,
                     "max_paren_depth":32},
 "components":[{"type","evidence_digest","evidence":{receipt_hash+metadata},
   "native_verifier_profile_digest":"oaa-raucle-verifier:0.23.5:63edacd",
   "trust_snapshot_digest","result":VERIFIED|ACCEPTED,"verification_status",
   "verifier_version","trust_policy_version","caid_mapping_verdict",
   "freshness":{checked_at,basis},"status_checks":[...]}]}
```

Determinism: no wall clock (injected `now`, second precision); all canonical
serialisation via JCS — two generations are byte-identical under an injected
clock (tested). The AEC body carries no time; only the replay record does.

## Evaluator limits (draft-fixed, enforced with rejection)

4096 bytes (UTF-8, not chars) / 256 tokens / 32 paren nesting levels; plus
grammar errors → `EVAL_LIMIT_BYTES | EVAL_LIMIT_TOKENS | EVAL_LIMIT_NESTING |
EVAL_PARSE`, bounded reason codes; missing atoms capped at 16 then
`EVAL_UNSATISFIED_ATOMS_TRUNCATED`. Rejection raises, never fabricates a
verdict; UNSATISFIED is recorded verbatim, not an error.

## JCS pitfalls hit (worth keeping as tests)

- ES6 number formatting: shortest round-trip repr via `Decimal`, trailing
  zeros from e.g. repr("2.0") must be removed **with exponent compensation**;
  thresholds n>21 and n≤-6 switch to exponential (`1e+21`, `5e-324`);
  -0 → "0"; integers must survive double round-trip (2^53+1 rejected).
- Key order is UTF-16 **code units**: astral U+10000 (units D800 DC00) sorts
  *before* U+E000, the opposite of code-point order — sort key must be
  `utf-16-be`, naive little-endian byte comparison is wrong.
- Lone surrogates escaped; RFC 8785 sample values covered by tests.

## Gaps vs the draft (EPIC M K1 scope only)

- **CAID profiles unimplemented**: `action_caid` is emitted as
  `caid:1:<tool>:sha256:<digest-b64url>` but marked descriptive; profile
  pinning (relying party matching a pinned CAID profile) is not wired —
  `caid_mapping_verdict` records `skipped_descriptive`.
- **Native verifier profile digest is a constant placeholder**
  (`oaa-raucle-verifier:0.23.5:63edacd`); actual verifier identity comes from
  evidence-plane classification results attached per component.
- **SCITT registration** (transparent receipt anchoring of the AEC digest)
  is future work — nothing registered anywhere in K1.
- Freshness is recorded as a basis string; no TTL/lease verification of
  receipt `iat` against a policy window yet.
- Requirement atoms are component-type ROLE labels only; no argument-scoped
  atoms (e.g. "tool == read_file") — that would be a richer grammar.

## What remains open (other legs)

- **EP-QUORUM**: multi-party quorum via H1 portal approvals (human approval as
  a component type) — needs a portal-approval evidence source; the evaluator
  grammar already supports the needed AND/OR over roles.
- **AEB effects leg**: what the agent *did* (K2 connectors: executed effects
  evidence) — the current AEC covers authorization evidence only; effect
  chains need their own object/leg.
- Trust snapshot currently digest-of-root-set; a future version may reference
  a signed trust-snapshot object instead.