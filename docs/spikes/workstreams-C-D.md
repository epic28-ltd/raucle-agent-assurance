# OAA Companion — Workstreams C & D (findings)

Date: 2026-11-04 (Europe/London). All research tool answers below cite primary
sources with version/commit and access date. Items marked **unmeasurable** were
not verifiable from primary sources; no substitute numbers appear.

Pins used in this document:
- OpenTelemetry GenAI semconv repo `open-telemetry/semantic-conventions-genai`, main @
  `633cbb060b16b1487ea2dcd23c4307edc1a03f01`, last commit 2026-11-04T00:49:31Z (accessed 2026-11-04).
  The repo has **no tags and no GitHub releases** (`api.github.com/repos/.../releases` and `/tags`
  both return `[]`, accessed 2026-11-04) — there is no pinned "version" of the spec, only `main`.
- Legacy `open-telemetry/semantic-conventions` v1.27.0 (`docs/gen-ai/gen-ai-spans.md`, tag v1.27.0).
- OpenInference `Arize-ai/openinference`, main @ `f1bf3e378ae7`, last commit 2026-11-02T18:13:33Z;
  latest published tag `python-openinference-semantic-conventions-v0.1.43` @ `9ed91c2780f2` (accessed 2026-11-04).
- raucle `github.com/epic28-ltd/raucle`: latest release tag **v0.23.5** (tagged 2026-10-30 17:34 GMT);
  local clone `origin/main` HEAD `2013a686a78610435eb27b9aed910c808808b4a2` is the same tree content plus
  unreleased `CHANGELOG.md` entries (commit date 2026-11-03, docs-only ahead of the tag). All code
  statements below were read and are attributable to HEAD `2013a686` unless noted.

---

## Workstream C — Trace semantics and portability

### C.1 Status of OpenTelemetry GenAI semantic conventions (`gen_ai.*`)

Two generations exist and both are live in the ecosystem:

1. **Legacy, embedded in `semantic-conventions` (deprecated).** As of the latest
   `semantic-conventions` release notes, **all `gen_ai.*` attributes, metrics, events and spans have
   been deprecated and moved** to the dedicated repository
   (source: `semantic-conventions` GitHub Releases page, migration tracked in issue #3696; accessed
   2026-11-04). The old `docs/gen-ai/` material was, in the last published version that carried it
   (v1.27.0, 2024-12), marked **Experimental**
   (source: `docs/gen-ai/gen-ai-spans.md` tag `v1.27.0`: "Status: Experimental"; accessed 2026-11-04).
2. **Current, dedicated repo `semantic-conventions-genai`.** All documents there are marked
   `**Status**: Development` at the pinned commit: `gen-ai-spans.md` and
   `gen-ai-agent-spans.md` both read "Status: Development" (accessed 2026-11-04). The doc tree is
   weaver-generation from `model/` YAML; it is now versioned by *attribute-level* stability badges
   (chips on each attribute row) rather than a single document status: `error.type`, `server.address`,
   `server.port` and the `_OTHER` enum members are `<Stable>`; nearly every `gen_ai.*` attribute
   (e.g. `gen_ai.request.model`, `gen_ai.response.model`, `gen_ai.agent.id`, `gen_ai.tool.name`,
   `gen_ai.retrieval.documents`) is `<Development>`; a few are marked candidate/rc in the model
   (the badge is applied per attribute, e.g. process path shown `rc` in the generated tables).

**Answer to the stability question: `gen_ai.*` is not stable and not yet experimental-as-frozen; the
current normative home marks the documents `Development`, with only shared/cross-domain attributes
(`error.type`, `server.*`) stable. Nothing in the GenAI namespace can be treated as a frozen wire
contract today.** Also structurally relevant: the repo has no release tags — implementers must pin a
commit SHA.

Recent substantive shape changes (from release notes of the legacy repo and the new repo docs,
accessed 2026-11-04): per-message events (`gen_ai.system.message` etc.) were replaced by
`gen_ai.system_instructions` / `gen_ai.input.messages` / `gen_ai.output.messages` attributes (or
`*_ref` pointers to uploaded content), plus a new `gen_ai.provider.name` discriminator and
`gen_ai.response.status` lifecycle. Any recorder/correlator built against pre-split conventions
must migrate.

### C.2 Span-kind coverage: agent runs, tool calls, retrieval, async handoffs

**OTel GenAI (pinned commit `633cbb0`):**

| Operation | Span (registry type) | OTel Span kind | Status |
|---|---|---|---|
| Agent creation (hosted agents) | `create_agent` | CLIENT | Development |
| Standalone agent invocation (client view) | `invoke_agent` client | CLIENT | Development |
| Agent invocation (framework view) | `invoke_agent` internal | INTERNAL | Development |
| Multi-agent orchestrator/graph | `invoke_workflow` | INTERNAL | Development; named examples: ADK `Runner.run`, CrewAI `Crew.kickoff()`, LangGraph `Graph.invoke()`, Microsoft Agent Framework, OpenAI Agents `Runner.run` |
| Planning phase | `plan` | INTERNAL | Development |
| Tool execution | `execute_tool` | INTERNAL (see §C.3 conflict) | Development (`gen-ai-spans.md`) |
| Agent hand-off via tool | refinement `execute_tool.transfer.internal` | INTERNAL | Development; carries `gen_ai.transfer.mode` (`return_to_caller` / `pass_control`) and `gen_ai.transfer.target.name`; explicitly "SHOULD NOT report additional spans for these tool calls"; "MUST NOT be used for transfers that do not happen through a tool call" |
| Retrieval | `retrieval` | CLIENT | Development |

Attributes that matter for correlation: `gen_ai.agent.id` (provider-assigned stable id; NOT
recommended for in-memory instance ids), `gen_ai.agent.name`, `gen_ai.conversation.id`
("if and only if the instrumented library has one readily available" — no synthesized UUIDs/fallbacks
allowed), `gen_ai.tool.call.id` (provider call id), `gen_ai.data_source.id`.

Extra spans at the pinned commit: `load_skill`, `read_skill_resource`, `command execution`
(agent-skills support), plus memory spans (`create/delete_memory`, `create/delete_memory_store`) —
Development.

**OpenInference (pinned commit `f1bf3e3`, spec pages; accessed 2026-11-04):**
Spans are ordinary OTel spans classified by a **required string attribute
`openinference.span.kind`** (not the OTel `SpanKind` enum). Span kinds per the spec docs page:
`LLM`, `EMBEDDING`, `CHAIN`, `RETRIEVER`, `RERANKER`, `TOOL`, `AGENT`, `GUARDRAIL`, `EVALUATOR`,
and additionally `PROMPT` and `DECISION` (listed in the semantic-conventions docs page). The
companion Rust port (`openinference-semantic-conventions`, non-exhaustive enum) implements
LLM/EMBEDDING/CHAIN/TOOL/AGENT/RETRIEVER/RERANKER/GUARDRAIL/EVALUATOR only — the docs page is the
superset. **Unmeasurable:** which of PROMPT/DECISION any given port realises.

Coverage vs OTel GenAI:

| Concept | OTel GenAI | OpenInference | Notes |
|---|---|---|---|
| Agent run | `invoke_agent` (+ separate `invoke_workflow`, `plan`) | single `AGENT` span "encompassing calls to LLMs and Tools" | OpenInference has no workflow/plan distinction |
| Tool call | `execute_tool`, `gen_ai.tool.call.id/arguments/result` | `TOOL` span | attribute sets differ (`input.value`/`output.value` raw JSON vs structured gen_ai tool-call objects) |
| Retrieval | `retrieval` span (`gen_ai.retrieval.top_k`, opt-in `documents`/`query.text`) | `RETRIEVER` span (`input.value` query, `input.document.*` content) | similar semantics, incompatible attribute names; `openinference.attribute.count` controls capture |
| Handoffs | `execute_tool.transfer` refinement with mode/target | **no first-class concept** (a handoff is a `TOOL` or `AGENT` span, unmarked) | see gaps |
| Async handoffs (queued/A2A-style) | **not represented in either spec** — `execute_tool.transfer` is a synchronous tool-call refinement; no A2A/queue semantics documented | none | see gaps |
| Guardrails | (no dedicated kind; guardrail scans are app-level) | `GUARDRAIL` kind | asymmetry to map |

Overlap/conflict summary:
- **Overlap:** both model the same four primitives (LLM call, tool call, retrieval, agent) and both
  are "on top of OpenTelemetry spans" — same wire format, competing attribute names.
- **Conflict 1 — span class taxonomy:** OTel GenAI uses the native OTel `SpanKind` (CLIENT for
  provider-facing calls, INTERNAL for framework-internal ones) *plus* `gen_ai.operation.name`;
  OpenInference ignores `SpanKind` semantics and requires `openinference.span.kind`. A trace from
  one camp carries no discoverable marker of the other's taxonomy except the attribute keys.
- **Conflict 2 — capture model:** OTel GenAI makes message/tool-argument content Opt-In with
  explicit SHOULD-NOT-capture defaults and external-storage `*_ref` pointers; OpenInference spans
  carry raw `input.value` / `output.value` with masking env vars. A correlator must not assume
  either capture model and must treat `*_ref` pointers as possibly-foreign storage.
- **Conflict 3 — names:** `ChatCompletion`-style span names vs `{operation.name} {model}` format;
  double-attribute spans must publish both name conventions or be joined by operation mapping.
- **Conflict 4 — identity:** `gen_ai.conversation.id` exists in OTel; OpenInference has
  `session.id` / `metadata` instead. Cross-camp conversation grouping is the key correlation join and
  is currently non-interoperable.

### C.3 What a backend-agnostic adapter must do

1. Emit **both label taxonomies** on every AI span: OTel `SpanKind` + `gen_ai.operation.name`, and
   `openinference.span.kind`; map them: `invoke_agent.*`/`invoke_workflow`/`plan` → `AGENT`;
   inference/embeddings → `LLM`/`EMBEDDING`; `retrieval` → `RETRIEVER`; `execute_tool` → `TOOL`;
   OpenInference `GUARDRAIL`/`EVALUATOR` have **no** OTel GenAI counterpart — keep them as extra
   kinds, don't fold into LLM/TOOL.
2. Pin a **commit SHA** of `semantic-conventions-genai`, not `main` (no releases exist), and record
   the schema_url per span since the legacy/new repos use different schema URLs.
3. Normalise content capture: support both "content Opt-In + `*_ref` pointers" (OTel) and "inline
   values + masking" (OpenInference); hash content if persistence is needed rather than assuming it
   is in-span.
4. Own the conversation join: since `gen_ai.conversation.id` may be absent by spec design, keep a
   companion-level conversation key (e.g. propagated baggage) rather than relying on instrumentors
   to emit one; never fabricate one to satisfy the spec.
5. Represent handoffs explicitly: map `execute_tool.transfer` to a companion "handoff" event with
   mode/target; for OpenInference-only traces infer handoff from TOOL spans to AGENT spans
   (heuristic — flagged as a gap below).

### C.4 Python instrumentation options and maturity (main agent frameworks)

Three families ship OTel-compatible Python instrumentation. All data accessed via PyPI
(versions/upload dates fetched from `pypi.org/pypi/<pkg>/json`, 2026-11-04) unless noted.

**A. Official OpenTelemetry, new GenAI family** (`open-telemetry/opentelemetry-python-genai`;
latest release wave `1.3b0`, 2026-10-23). Beta-quality — package versions are `1.x**b0**`, which the
project itself publishes as pre-release (`b0`). Instrumentors available at the pinned date:
OpenAI (`genai-openai` 1.3b0), OpenAI Agents SDK (`genai-openai-agents` 1.3b0 — workflow/agent/tool
spans, no LLM spans; continues an earlier separately-published package `openai-agents-v2`),
Anthropic, Bedrock, Claude Agent SDK, CrewAI, DSPy, LangChain, LlamaIndex, Google GenAI
(`google-genai` 1.3b0), Agno, SmolAgents, Qwen Agent, Portkey, Weaviate client. Notably **no
AutoGen/AG2 and no Microsoft Agent Framework instrumentor** in that directory as of 2026-11-04.

**B. OpenInference instrumentors** (`Arize-ai/openinference`), OpenInference-style spans; very
actively released (2026-10-29) but pre-1.0 for the core ones: langchain 0.1.81, crewai 1.1.22,
llama-index 4.7.0, openai-agents 2.7.0, plus autogen/ag2 variants
(`openinference-instrumentation-autogen`, `-autogen-agentchat`). These are the de-facto production
choice for Phoenix/Arize backends; **unverifiable** claim of conformance to OTel GenAI — they target
the OpenInference spec, which conflicts as in §C.3.

**C. Independent community packages** (`opentelemetry-instrumentation-langchain` 0.62.4,
`opentelemetry-instrumentation-crewai` 0.62.4, `opentelemetry-instrumentation-openai-agents`
0.62.4, release 2026-09-29; per piwheels mirror which lists the 0.x series back to 2025-2026) +
Google ADK relies on `opentelemetry-instrumentation-google-genai` (pinned `<2,>=0.7b1` dependency by
`google-adk` 2.13.0's `otel` extra). This family is third-party-maintained (not in
open-telemetry CI), emits legacy `gen_ai` + GenAI-OTel attributes and is the widest-deployed for
LangChain-style stacks. **Unmeasurable:** maintenance-owner identity/SLA from PyPI metadata alone.

Maturity verdict: nothing Python-side is at a stable 1.x (non-beta) release in either official or
OpenInference families; the ecosystem is beta-grade but fast-moving. The companion should treat
instrumentor output as unstable input and do its own correlation layer, not rely on instrumentor
attributes as contract.

---

## Workstream D — Evidence and trust model of raucle

Pin: **tag `v0.23.5` (2026-10-30)**; code statements below verified at HEAD `2013a686a78610435eb27b9aed910c808808b4a2`
(local clone, same tree family). Spec: `docs/spec/provenance/v1.md` (Draft 2.2 changelog row: pq1
added 2026-09-05), plus documented companions: `v1/pq1-hybrid.md`, `v1/conformance-reverification.md`,
`docs/spec/time-source-v1.md` (accepted 2026-10-30), `docs/security/key-operations.md`.

### D.1 Canonicalisation — proven in code
- Spec §4.3: JSON canonicalisation = RFC 8785 (JCS) **integer-only subset**: keys at every depth sorted
  by **UTF-16 code unit** (RFC 8785 §3.2.3), no whitespace, UTF-8, non-ASCII unescaped, floats
  rejected, integers confined to ±(2⁵³−1) (JS safe range), and (in code) lone surrogates rejected.
- Proven: `raucle/_canon.py` (`reject_lone_surrogates`, `utf16_key`, `reorder_keys_utf16`),
  `raucle/provenance.py` `_reject_floats` (safe-range check). Machine-checked cross-language:
  `docs/spec/provenance/v1/test-vectors.json` with three vector groups (byte-reproducible receipts
  from fixed seeds; isolated canonicalisation vectors; must-reject invalid vectors), and **five
  reference implementations (Python/TS/Go/Rust/C# under `reference/`) pinned to it** (asserted in
  spec §14/App B that they were cross-verified to byte-identical receipt IDs; the Python side and the
  vectors are in this repo, the other ports' CI is **unmeasurable** from here).
- Legacy format: pre-v0.17 denormalised JSONL envelopes no longer accepted, only the minimal
  `{receipt_hash, jws}` envelope, with `raucle provenance migrate-envelope` gating re-writes on
  signature verification (spec §9 + code).

### D.2 Signature scheme
- **Compact JWS (RFC 7515), `alg` fixed `EdDSA` over Ed25519** (RFC 8037); `alg=none` or any other
  algorithm MUST be rejected; mandatory `crit: ["raucle/v1"]` (blocks JWT-bearer confusion via RFC
  7515 §4.1.11 semantics) and `typ: "provenance-receipt/v1"`; `kid` = first 16 lowercase hex chars of
  sha256(SPKI PEM public key). Code: `raucle/provenance.py` (header enforcement incl. duplicate-key
  rejection, kid↔payload binding).
- **Post-quantum profile `raucle/pq1`** (v0.23): hybrid Ed25519 + **ML-DSA-65 (FIPS 204)** in the
  signature slot as two base64url segments (`kid` + `pqk`); both must verify (AND), no downgrade
  path; `crit` includes `raucle/pq1` so unaware verifiers reject. Note: hybrid receipts are **not
  byte-reproducible** across implementations (FIPS 204 signing is hedged/randomised); the port
  contract is verification-based, with `docs/spec/provenance/v1/pq1-test-vectors.json`
  (key-derivation, prefix byte-match, verify-reference-signature, verify-own-signatures) — asserted
  for the other ports ("Python reference authoritative"); Python side has `raucle/pq.py`
  (`HybridSigner`, `verify_hybrid`) and a `require_pq`/`pq_public_keys` verifier path
  (`provenance.py` `__init__`).

### D.3 Checkpoints and TSA behaviour
- **Local checkpoints:** `raucle/audit.py` `HashChainSink` — hash-chained audit log with an
  **Ed25519-signed checkpoint every N events (default 1000) and on close**; skipping checkpoints is
  a distinct documented fail-mode (code docstring: "cannot produce checkpoint signatures that any
  downstream..."). The **trust registry is itself an append-only operator-signed chain**
  (`_verify_chain_entries`, `_verify_operator_signatures`, hybrid dual-key signatures in pq1 mode;
  `_resolve_operator_pq_key`).
- **TSA / time source (v1 spec companion, accepted 2026-10-30):** three documented modes:
  1. **internal** (default) — host clock under a documented discipline; claims bounded time only.
  2. **TSA-attested** (RFC 3161) — **customer-chosen, hash-only** TimeStampReq (SHA-256 digest
     embedded in an `x_timestamp` extension receipt: digest, parent cite, TSA URL, nonce (52-bit, to
     fit the safe-integer canonicalisation contract), embedded DER TimeStampToken, genTime, serial,
     policy OID). Verification is offline and fail-closed (asn1crypto parse; token re-check:
     message imprint, nonce, mandatory signed attrs, genTime within cert validity, TSA signature,
     optional pinned TSA key; recorded genTime must equal token's). Installs without the
     `raucle[timestamp]` extra fail closed with a named error. Anchoring is periodic on the chain
     head, not per receipt ("economically wrong" per receipts; cadence guidance in the doc).
  3. **OpenTimestamps** — .ots proof; offline verifier checks digest/cite only, does NOT verify
     Bitcoin; no eIDAS Art 41 presumption (explicitly documented).
- Long archives: `raucle timestamp plan` computes an archive horizon from `retention_until` (G3) and
  reports restamp-by dates (cert expiry minus 30-day window); re-stamping = new anchor over the SAME
  digest; countersigning never replaces old evidence. Critical gotcha: the anchor digest binds the
  **exact raw ledger line bytes** — chain exports must preserve lines verbatim or anchors must be
  re-minted.
- Tested by `tests/test_timestamping.py` (mock RFC 3161 TSA; tamper, ghost-cite, genTime-tamper,
  pinned-key mismatch, missing-extra fail-closed cases are named in the doc).

### D.4 Key discovery, rotation, revocation, historic verification
- **Discovery:** agent identity = `agent_id` (strict regex, dot-delimited scoping, trailing `..`
  forbidden) + Ed25519 keypair; the public key is distributed via a signed **capability statement**
  (Ed25519 over canonical JSON, standard-alphabet signature), and verifiers consume a **trust
  registry** (`raucle/trust_registry.py`: `publish`, `publish_pq_key`, `resolve`, `resolve_pq_key`,
  `revoke`, `is_revoked`, `public_key`), which enforces **one active classical key per issuer name**
  (`_check_issuer_uniqueness`) and integrity via its own signed chain. Fail-closed: an
  `agent_key_id` not covered by any supplied statement is a violation (spec §10 step 7).
- **Rotation:** registry rotation is done by minting under a **versioned issuer identity**
  (`acme.bank/v2`), dual-trust window, then `registry revoke <old-key-id>`. Gateway signing-key
  rotation is a restart procedure with the archived PEM. **Proven in code/tests:** each of the four
  post-conditions (new mints under old key fail closed; pre-rotation tokens verify during the window;
  revoked generation fails closed; audit packs verify with bundled `--pubkeys`, several accepted) is
  backed by `tests/test_key_rotation_e2e.py`.
- **Revocation semantics:** deliberately **no CRL for receipts/tokens in v1** (spec §2.2 non-goal and
  Appendix C): revocation is layered — short capability TTLs (60–300s in examples), attenuation,
  gate denylist (`revoked_token_ids` + `revoke()`, deny covers children citing revoked parents —
  code in `raucle/capability.py`; only *immediate* parent cited checked, a documented limitation),
  and key removal from a gate/registry. A signed distributable revocation feed is scoped as future.
- **Historic receipts after rotation: YES, still verifiable.** `verify_chain` verifies entirely
  against the `public_keys` mapping supplied to the verifier (plus optional `capabilities`,
  `pq_public_keys`); registry revocation removes trust but "the math stands" — signatures made
  before revocation verify against the public key forever (key-operations.md). The practical
  requirement is **key archival discipline**: audit packs bundle `--pubkeys` for this. So the
  answer is: verification remains possible iff the public keys (and, for pq1, the ML-DSA keys) are
  archived; the wire format itself does not discover or distribute old keys, and receipt-chain
  verification does **not** consult registry revocation state — revocation is a gate-time
  authorisation concern, not an archival-verification concern.

### D.5 Selective disclosure
- **Implemented in code**: `raucle/conformance.py` — `commit_args` (Merkle tree over top-level
  fields; leaves `sha256("raucle/d1\x00l\x00"+f+"\x00"+canonical_json(v))`, field-name order in
  UTF-16 code-unit order; domain-separated internal nodes; self-pairing odd nodes; empty root
  constant), `verify_disclosure` (fail-closed path folding), `recheck_constraints` (returns
  SATISFIED / VIOLATED / **UNKNOWN**; UNKNOWN is fail-closed; re-check implemented independently of
  the gate). Tests: `tests/test_conformance.py`, `tests/test_spec_conformance.py`.
- **Not yet on the wire:** the richer commitment would live in a future `x_args_commitment` receipt
  extension; today receipts commit only `args_hash`. zkVM (Layer 2) and ZK (Layer 3) are declared
  future work. Disclosure vector file (`disclosure-vectors.json`) is planned, not present
  (`docs/spec/provenance/v1/` listing, accessed 2026-11-04).

### D.6 Formal model — proven vs asserted
- **Proven (mechanised):** Lean 4 development `paper/lean/VCD/` (Basic, Gate, Composition,
  Attenuation) — 9 `theorem`s including `attenuation_soundness`, `gate_soundness`,
  `policy_proof_composition`, `tighter_implies_satisfies`; grep found **zero `sorry`/`admit`** in the
  four files (checked 2026-11-04). Scope: the **capability/policy/gate layer** (VCD) only —
  policy soundness over tool schema, attenuation, gate enforcement.
- **NOT mechanised (asserted as prose):** the receipt layer — canonicalisation equivalence to the
  vectors (machine-checked by tests, not proof), taint monotonicity enforcement, DAG integrity,
  timestamp verification semantics, revocation behaviour. The paper's own §8 "Limitations" states
  the true scope honestly: bounded tool-call surface only (free-form output unprotected), conserved
  JSON-Schema fragment (no oneOf/anyOf yet), parameter-space side channels, confused-deputy
  multi-call sequences (handled by the provenance layer, integration asserted), argument privacy in
  re-verification (UNKNOWN→SATISFIED needs future zk proofs), issuer-key compromise treated as out
  of scope (bootstrap trust), intent-extraction as a second trust boundary (three designs listed,
  only rule-based preserves the property end-to-end), defender authoring effort.
- **Where claims rest on operator honesty rather than crypto:** the "lying agent" (wrong
  `input_hash`) and clock independence (Mode 1) are explicitly documented as not defended against.

---

## Ranked open gaps affecting the companion's correlation design

1. **No stability contract on the trace side.** OTel GenAI docs are `Development` with per-attribute
   chips, and the repo has no tags/releases; legacy `gen_ai.*` in `semantic-conventions` is
   deprecated. Any correlator keyed to `gen_ai.*` attribute names must pin a commit SHA and tolerate
   both legacy and split generations in the wild (field evidence shows both in deployment).
2. **Dual-taxonomy ambiguity.** OTel `SpanKind`+`gen_ai.operation.name` vs `openinference.span.kind`
   are concurrent, non-equivalent taxonomies over the same OTel wire format; kinds like
   GUARDRAIL/EVALUATOR (OpenInference) and `plan`/`invoke_workflow`/agent-transfer-refinement (OTel)
   have no counterpart. The adapter must carry both attributes and an explicit mapping table, and
   the mapping is lossy for guardrail/evaluator spans.
3. **Async handoffs are not represented in either spec.** `execute_tool.transfer` covers only
   synchronous tool-mediated transfer; queue/A2A-style async handoff has no span, kind, or
   attribute convention. Cross-process async correlation must be a companion-defined mechanism
   (own correlation id or W3C context propagation) — flagged as design work, not derivable from
   either spec.
4. **Conversation/session join is spec-softened.** `gen_ai.conversation.id` must not be
   synthesized and is absent when the library doesn't have one; OpenInference has a different
   session notion. The companion must own a conversation-scoped correlation key end-to-end.
5. **Python instrumentation is beta everywhere** (official `1.x b0`; OpenInference core packages
   0.x-2.x; community family 0.62.x), with overlapping coverage of the same frameworks (LangChain,
   CrewAI, openai-agents, LlamaIndex available in all three families). Running two families on one
   process yields duplicate, differently-shaped traces; the rollout plan must pick one family per
   process and normalise at the companion boundary. No non-beta AutoGen/AG2 or Microsoft Agent
   Framework official package as of 2026-11-04.
6. **raucle verifier needs keys and statements shipped with the evidence.** Verification is offline
   and only against supplied `public_keys`/`pq_public_keys`/capability statements; no key discovery
   is on the wire. Correlated bundles (companion exports) must always carry the audit pack's
   `--pubkeys` and statements or chains become unverifiable — a packaging requirement on the
   correlation design, not an opt-out.
7. **Receipt-level revocation is absent by design.** No CRL; revoked keys still verify. If a
   regulatory customer expects "revoked ⇒ old receipts invalid," the companion must present the
   registry revocation timeline separately from receipt verification, or trust-model confusion
   follows.
8. **TSA anchors bind exact ledger-line bytes.** Any export/normalisation step in the companion
   pipeline that re-serialises chains invalidates `x_timestamp` re-derivation; correlation tooling
   must treat chain files as byte-opaque or force explicit re-anchoring.
9. **Selective disclosure not yet committed on the wire.** Receipts hold only `args_hash`; the
   Merkle `x_args_commitment` extension, disclosure vectors, zkVM Layer 2 are future. Content-level
   correlation across receipts and traces can't join on arguments until disclosure happens or the
   extension lands.
10. **pq1 breaks byte-reproducibility assumptions in tooling.** Hybrid receipts are not
    byte-reproducible across implementations (hedged ML-DSA signing); anything in the companion
    that assumes deterministic wire bytes (dedup, exact-match joins, canonical receipts in
    correlation keys) must special-case pq1.
11. **Formal-model scope must be quoted precisely.** Lean covers the capability/gate layer only
    (0 sorries); receipt canonicalisation/taint/DAG/TSA are test-vectored and code-enforced, not
    mechanised. Companion docs must not inherit "formally verified" claims for the receipt layer.
12. **No replay-window enforcement in the receipt spec.** Re-emitting a valid receipt chain into
    another chain is detectable but not rejected by the verifier; deduplication/uniqueness for
    correlated evidence is the companion's job.