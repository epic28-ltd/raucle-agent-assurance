# Supported agent runtime and adapter matrix

Version 1. This document is the response to assurance issue 114: an inventory
of every shipped adapter and in-process framework handler across
`epic28-ltd/raucle-agent-assurance` and the OSS `epic28-ltd/raucle` tree, with
supported versions (cited from the packages' own pins and CI workflows),
enforcement points, context propagation mechanisms, identity handling and
known limitations.

## Scope and method

- **Scope.** Runtime adapters and framework handlers shipped in the two
  repositories, as read from the trees named in each row. Evidence-plane,
  observability and export components are listed because the issue asks for
  integration points, but each row states honestly whether it can intercept
  traffic at all.
- **Method.** Every row was read from the actual trees at the commits cited
  in the row: the assurance repository at the time of this document's edit,
  and the OSS raucle tree at its `main` branch. Version spans are quoted from
  the `pyproject.toml` extras (including the in-file verification notes) and
  from the CI workflow files of each repository; nothing in this matrix is
  derived from vendor marketing or unverifiable changelog claims.
- **Claim discipline.** Transparent interception is claimed ONLY where every
  relevant traffic path is demonstrably covered. No row in this matrix makes
  that claim: every integration intercepts only the specific seam it names,
  and anything short of full traffic-path coverage is named as an explicit
  boundary row in section 6.

## 1. Enforcement doctrine (binding across all rows)

- **In-process handlers are observability, not a security boundary.** The
  framework handlers in the OSS raucle tree (section 4) run inside the agent
  process. They gate tool calls before the body runs and they emit signed
  receipts, but a compromised or mis-configured host process can bypass
  them by construction. They are an observability and policy-feedback
  surface only.
- **The hard boundary is the out-of-process gate plus credential isolation.**
  The assurance adapters (section 2 and section 3) enforce by calling a gate
  that runs outside the agent process; verification material (trusted keys,
  credentials) is not required to live in the agent's memory for a decision
  to be made. Only out-of-process enforcement counts as a security boundary.
- **Identity doctrine.** An ALLOWED execution always carries a real acting
  identity. A call with no bound caller identity denies, and the deny receipt
  records an honest null identity rather than a fabricated or placeholder
  identity (the B2 "bearer mode is closed" doctrine implemented in the OSS
  `raucle.integrations._guard_core` helpers and enforced by the gate).

## 2. Assurance adapters (repository: epic28-ltd/raucle-agent-assurance)

| # | Adapter | Repository path | Enforcement point | Supported versions (cited) | Context propagation | Identity handling |
|---|---------|-----------------|-------------------|----------------------------|---------------------|-------------------|
| A1 | Raucle Gate LangGraph adapter (`oaa-langgraph-adapter` 0.1.0) | `integrations/langgraph-adapter` | Out-of-process gate. `RaucleGateMiddleware.wrap_tool_call` vetoes by not calling `execute`; every tool call crosses `HttpGateClient` against a running gate service, or `InProcessRaucleGate` against the pinned raucle gateway embedded in-process. The adapter CALLS the gate; it is never the gate. | Python >= 3.11. `langchain`/`langgraph` are not required to install or test (the `ToolCallRequest` shape is mirrored with a local TypedDict; `AgentMiddleware` registration is attempted only when langchain is importable). Documented wiring target: `langchain >= 0.3`. Pinned Raucle distribution for the in-process client: `raucle 0.23.6 (git 645f5de)` (`RAUCLE_DISTRIBUTION_PIN`). | Correlation id: `tool_call` id is the gate `call_id`; `trace_id` from a pluggable `trace_context_getter` (default getter greps `trace_id`, `trace-id`, `oaa_trace_id`, `thread_id` off `request["runtime"]`/`state`). W3C `traceparent`/`tracestate` headers, where a getter supplies them, ride the gate event unmodified (never parsed by the middleware, never allowed to influence the decision; oversized `tracestate` is dropped). Receipt hash and verification state land on span attributes through callback sinks only (no direct OpenTelemetry import in this package). | The middleware never fabricates identity. `agent_id` is middleware configuration (documented K3 gap: not derived from graph state); a getter-supplied identity is forwarded verbatim and wins over configuration; an empty configured identity reaches the gate as empty so the gate's own deny-on-unattributed doctrine applies. Bound by contract tests `integrations/langgraph-adapter/tests/adapter/test_contract_identity_replay.py` (added with this matrix). |
| A2 | Raucle evidence adapter (`oaa-raucle-adapter` 0.0.1.dev0) | `packages/raucle-adapter` | None (evidence plane). Verbatim store for the gate's `{receipt_hash, jws}` bytes, sha-verified in and out; derived state lives in a separate index. Canonical evidence is never mutated. | Python >= 3.11. Raucle is an optional, pinned dependency: `raucle 0.23.6 (git 645f5de)`. | Receipt correlation by `receipt_hash` and the signed `x_gate.trace_id` (authoritative where present; correlation is a hint, not authentication). Trust roots are versioned and selected by `key_id` and event time. | No identity of its own: the adapter records the gate's receipts; identity binding inside a receipt is the gate's own. Audit-source records never invent a principal (see A5 and B7). |
| A3 | OTel instrumentation (`oaa-instrumentation` 0.0.1.dev0) | `packages/instrumentation` | None (observability only, invariant 3: the companion is never the enforcement authority). Deterministic SDK-side span-attribute redaction, loss-counted OTLP export, decision-span sinks for gate events, collector-side quarantine config. | Python >= 3.11. Optional `otel` extra pins `opentelemetry-sdk >= 1.38`, `opentelemetry-exporter-otlp-proto-http >= 1.38` and `pyyaml` (comment in `packages/instrumentation/pyproject.toml`). CI verifies against a pinned OpenTelemetry Collector Contrib `0.120.0` (`.github/workflows/ci.yml`, `otlp-collector-integration`). | W3C `traceparent`/`tracecontext` propagation (issue 111); decision spans join the upstream trace from the gate event's validated headers; export uses bounded retry with explicit loss counters and a post-loss marker span. | Trace identity only (trace/span ids). Payload secrets are redacted with deterministic markers, verified against a real collector in CI. |
| A4 | Audit evidence chain generator (`oaa-epaec`, packages/ep-aec) | `packages/ep-aec` | None (evidence packaging). JCS-canonical evidence objects and a seeded 100-case regression corpus (EVAL-01). | Python >= 3.11. | N/A (packaging; consumes gate-adjacent evidence records). | Records supplied identities only; no minting. |
| A5 | Audit-source normalisers (`oaa-audit-sources` 0.1.0) | `integrations/audit-sources` | None (reconciliation). Offline normalisers for export-tooling audit sources (CloudTrail, GitHub) plus gate/audit reconciliation (EPIC M K2). | Python >= 3.11. | Reconciles normalised source records against gate and audit events. | Normalised records map unknown actors to an explicit unknown state; no principal is guessed. |
| A6 | SIEM webhook exporter (`integrations/siem`) | `integrations/siem` | None (export path only). Stable event envelope, dedupe by source event id, bounded retry with dead-letter. | Python >= 3.11 (root suite). | Vendor event id dedupe; envelope is byte-stable across runs for the same event. | Never puts a secret in the envelope (tested); no invented identities. |
| A7 | Backend trace adapter (`integrations/backends`) | `integrations/backends` | None. README-only placeholder (ADR 0003 backend adapter); not shipped. | None. | None. | None. Marked unsupported (see B4). |

### A-row limitations

- **A1 (cited from `docs/spikes/K3-adapter-findings.md`):** only the sync
  `wrap_tool_call` hook is implemented (async graphs need `awrap_tool_call`);
  streaming denial surfacing is runtime-dependent and untested (the deny
  still vetoes before streamed tool output can leak); `escalate` resolves to
  deny and no approval resubmission path (`approval_id`) is wired; `trace_id`
  extraction is a heuristic over common state keys and per-team getters may
  be needed; there is no pre-gate attempt span; `InProcessRaucleGate` keys
  behaviour on the distribution pin constant, so an embedded gateway must
  match the pin; plain HTTP is accepted only for exact loopback hosts.
- **A2:** requires the pinned Raucle distribution; signature verification
  states are schema-distinguishable (unknown, invalid, not_applicable,
  pending) and `valid` is never inferred from missing data.
- **A3:** redaction is tested, not promised; telemetry loss must be visible,
  not silent (bounded retry, loss counters, post-loss marker span).
- **A6:** dead-letter after bounded retry; a 4xx fails without retry.

## 3. Enforcement contract tests shipped with this matrix

The one out-of-process enforcement adapter (A1) was missing explicit identity
and replay contract tests. `integrations/langgraph-adapter/tests/adapter/test_contract_identity_replay.py`
binds, at the real seam (`wrap_tool_call` and the single gate call behind it):

- **identity:** an empty configured identity is forwarded to the gate as
  empty (never fabricated, never defaulted); the default getter never lifts
  an `agent_id` out of graph state (identity is configuration, not
  harvestable); a getter-supplied identity is forwarded verbatim; an
  unattributed call still depends on the gate for the decision because the
  adapter is not the gate; an allow without a signed receipt is a veto even
  with an empty identity; the gate request and the audit event carry exactly
  the same acting identity.
- **replay:** there is no decision or receipt cache. An invocation repeated
  with an identical correlation id issues exactly one further gate call with
  the same id, and a previously recorded ALLOW never pre-authorises a later
  call locally: the gate is consulted for every invocation.
- **error handling and no-retry:** a gate exception is exactly one gate call
  (never retried in the enforcement path); under the default fail-closed mode
  the tool body never runs and the audit event carries the error; under
  explicit `fail_open=True` the call proceeds unverified with the span marked
  `oaa.verification="unverified"` and no receipt hash attached.

Other assurance adapters already have bounded contracts in the root suite and
none needed new seams: the evidence adapter's replay tamper and roundtrip
contracts live in `tests/conformance/test_evidence_plane_binding.py` and
`tests/audit-pack/test_replay_binding.py`; the SIEM exporter's retry,
dead-letter, dedupe and secret-freedom contracts live in
`tests/integrations-siem/test_webhook.py`; the instrumentation redaction,
loss and propagation contracts live in `tests/otel/`. Rows without their own
identity/integrity/replay/error contract set are named in section 7 rather
than implied to have one.

## 4. In-process framework handlers (repository: epic28-ltd/raucle, `raucle/integrations/`)

All rows in this table are IN-PROCESS handlers: observability and
policy-feedback surfaces, NOT a security boundary (section 1). A deny still
prevents the wrapped tool body from running at the seam, and every decision
is receipted, but the hard boundary remains the out-of-process gate plus
credential isolation.

| # | Handler | Framework seam | Pin (from `pyproject.toml` extras) | CI verification | Context propagation | Identity handling |
|---|---------|----------------|-------------------------------------|-----------------|---------------------|------|
| R1 | `langchain` (`RaucleCallbackHandler`) | `langchain-core` `BaseCallbackHandler` intercepting tool invocations in an `AgentExecutor`/`Runnable` graph | `langchain-core >= 0.3`, `cryptography >= 42.0` | Main CI matrix (Python 3.11/3.12/3.13): the `dev` extra installs `langchain`, so `tests/test_langchain_integration.py` runs rather than skips | In-force capability token via `set_in_force_token`; receipts to the caller-supplied sink | Gate-core doctrine: no caller identity, no allow; deny is receipted honestly |
| R2 | `langgraph` (`gate_tool`/`gate_tools`, `RaucleToolNode`) | Wraps the tool node layer (`langgraph.prebuilt.ToolNode` drop-in); the model node is untouched | `langgraph >= 0.2` | `test-integration-extras` job (Python 3.13) runs `tests/test_langgraph_integration.py` | Same in-force token mechanism; receipts both ways | Same gate-core doctrine |
| R3 | `crewai` (`guard_tool`/`guard_tools`) | Wraps `crewai.tools.BaseTool`; `CapabilityDenied` surfaces to the agent and the tool body never runs | `crewai >= 1.0, < 1.16` | Verified span 1.0.0, 1.5.0, 1.6.1, 1.15.41 (D1 note in `pyproject.toml`); CI extras job (Python 3.13) | Same | Bearer mode closed: a valid token does not authorise an unattributed call (D1) |
| R4 | `autogen` (`gated_tools`) | Wraps `autogen_core.tools.FunctionTool` (0.4 `run_json` shape) | `autogen-agentchat >= 0.4` | Stub-backed suite runs in the main matrix; NO CI job installs the real extra (see B3) | Same | Same |
| R5 | `pydantic-ai` (`guard_tool`) | Wraps `@agent.tool`/`@agent.tool_plain` callables via `functools.wraps` so the framework sees an identical tool | `pydantic-ai >= 1.107, < 3` | Verified spans 1.107.10, 2.59.0, 2.65.0, 2.70.0 (P2a note, CPython 3.13); CI `test-integration-extras-p2a` job | Acting identity resolution order: guard-time `agent_id`, else `RunContext.agent.name`, else deny | Unattributed call denies (D1); context supplies identity when pinned value absent |
| R6 | `openai-agents` (`input_guardrail`, `output_guardrail`, `guard_tool`) | SDK guardrail hooks scanning prompt/final output; wraps SDK `FunctionTool` objects with the capability gate | `openai-agents >= 0.19, < 0.26` (verified 0.19.1, 0.21.0, 0.23.1, 0.25.0, P2a) | Installed via the `dev` extra on the main matrix (3.11/3.12/3.13) and listed in the P2a job | Scanner receipts emitted for clean and flagged scans alike; scanner failure trips the wire (fail-closed) | Same gate-core doctrine for the capability path |
| R7 | `google-adk` (`guard_tool`) | Wraps plain functions with `ToolContext` (and `google.adk.tools.FunctionTool`) | `google-adk >= 1.39, < 3` (verified 1.39.1, 2.7.0, 2.11.0, 2.14.1, Apache-2.0, Python >= 3.11) | CI P2a job | Identity rides the invocation context: ADK names join the raucle namespace deterministically (an ADK agent named `billing_agent` acts as `agent:billing_agent`; scheme-valid names pass through) | Unattributed call denies |
| R8 | Microsoft Agent Framework middleware (`RaucleFunctionMiddleware`) | Drop-in `FunctionMiddleware` on `agent_framework.ChatAgent` | `agent-framework >= 1.0` | Stub-backed suite only; NO CI job installs the real extra (see B3) | Same in-force token mechanism | Same |
| R9 | Microsoft AGT Policy Decision Point (`RauclePolicyProvider`, `agt_backend`) | Reference implementation of an `IPolicyProvider` proposal-shape stub (upstream contract not yet landed) | None (stdlib; wired against `agent-framework` at runtime) | Stub-backed decision tests (`legacy AGT degradation`, `sub-agent id` matching) | Receipts through the AGT backend decision pointer | Unattributed/no-token decision denies; legacy AGT verdicts stay correct with assurance fields dropped |
| R10 | QM harness adapter (`qm`) | Task hand-off wiring for QM-class harnesses: `mint_for_task`, `gate_call`, `bilateral_outcome`, one static wiring bundle | None (core + `cryptography`) | `tests/test_qm_live_integration.py` in the main matrix | Delegated-authority chain bound into the receipt | The principal mints an attenuated capability per task; bilateral outcome co-signature is fail-closed when missing or failing verification |
| R11 | Audit-source connectors (`raucle/connectors`) | Pull transports mapping vendor audit streams (Okta System Log, GitHub audit-log and similar control planes) to raucle chain events | None (stdlib; fixtures offline) | Main matrix | Vendor event id idempotency (paginated redeliveries dedupe) | Hard rule: no invented identities. A vendor event without an attributable actor maps to an explicit unknown state with a machine-readable reason |

### R-row limitations (common to all in-process handlers)

- The interception window is exactly the named seam. Nothing outside that
  seam (model/LLM traffic, framework-internal planning, non-tool output
  paths, direct HTTP the host process performs) is intercepted, which is
  acceptable precisely because these handlers are observability surfaces and
  the security boundary lives in the out-of-process gate.
- Versions are recorded as pins plus the verified spans cited above. A span
  records VERIFICATION, not a behavioural limit; lifting a bound is a
  deliberate act after the corresponding CI job re-verifies (the project's
  stated convention in `raucle/pyproject.toml`).
- The `pydantic-ai` and `google-adk` extras cannot co-install with the
  `crewai` extra at their verified spans (joint resolution downgrades both to
  pre-1.0 releases), so they run in a separate CI slot and deployments should
  install at most one family per environment (P2a investigation note,
  2026-11-18).

## 5. Roadmap evaluation: AutoGen, LlamaIndex, Semantic Kernel, Kong, Envoy, cloud API gateways

| Target | Current shipped state | Candidate for | Prioritisation criteria (no dates, no demand claims) |
|--------|----------------------|---------------|------------------------------------------------------|
| AutoGen | In-process handler shipped in OSS (R4, stub-backed CI); no assurance adapter | Assurance out-of-process adapter, if and only if AutoGen's runtime offers a gateable out-of-process seam; otherwise the in-process handler remains an observability surface | C1, C3, C5 below |
| LlamaIndex | Not shipped in either repository | Either integration shape | C1 to C6 below |
| Semantic Kernel | Not shipped in either repository | Either integration shape | C1 to C6 below |
| Kong | Not shipped; no gateway adapter exists anywhere in the suite | Gateway adapter | C1, C2, C4, C6; per issue 114 a gateway adapter additionally requires a threat model and bypass tests BEFORE any production claim |
| Envoy | Not shipped; no gateway adapter exists anywhere in the suite | Gateway adapter | As for Kong |
| Cloud API gateways | Not shipped; no gateway adapter exists anywhere in the suite | Gateway adapter, one vendor at a time | As for Kong |

Prioritisation criteria, in the order they are applied:

- **C1. Out-of-process gateability:** does the target expose an enforcement
  seam that can call a gate running outside the agent process, without the
  decision depending on trust inside the process?
- **C2. Traffic-path coverage verifiability:** can the full set of relevant
  call paths be enumerated and covered by tests, so a transparent-interception
  claim would be defensible rather than aspirational?
- **C3. Version stability and maintenance footprint:** does the target keep a
  stable extension surface across a pinned version span that the project can
  afford to verify on every release?
- **C4. Credential isolation compatibility:** can verification material stay
  out of the agent process while decisions are taken?
- **C5. Contract testability at bounded seams:** can identity, request
  integrity, replay and error-handling contracts be asserted at real seams
  without installing fragile upstream stacks into every CI run?
- **C6. Recorded demand:** priorities may cite only demand already recorded
  in project trackers; demand is never invented or extrapolated for a row.

## 6. Boundary rows (explicit; each one names why transparent interception is NOT claimed)

- **B1. No shipped row claims transparent interception.** Every OSS handler
  (R1 to R11) covers exactly its named seam; the assurance adapter A1 covers
  tool calls crossing the AgentMiddleware hook. Nothing in the suite
  demonstrably covers all relevant traffic paths of a runtime, so no
  transparent-interception claim is made anywhere (issue 114's explicit rule).
- **B2. A1 concrete shortfalls:** sync hook only; streaming denial surfacing
  untested; `escalate` unresolved to a deny without an approval path;
  `agent_id` is configuration rather than graph-derived state; the model path
  is untouched by design. These are acceptable only because enforcement
  authority is the gate service, not the adapter.
- **B3. R4 (AutoGen) and R8 (Agent Framework) are stub-verified only:** their
  contract suites run against mirrored tool shapes, and no CI job installs
  the real extra, so their "supported versions" mean the pin, not a
  CI-verified real-SDK span. Treat real-SDK claims for these two rows as
  unverified until a CI slot installs them.
- **B4. Unsupported runtimes are explicit:** LlamaIndex, Semantic Kernel,
  Kong, Envoy and cloud API gateway integrations are NOT shipped (A7 is a
  README placeholder for a backend adapter and likewise not shipped). Until a
  row graduates through the criteria in section 5, and pass the threat model
  plus bypass tests the issue requires for gateways, these targets are
  unsupported.
- **B5. CI coverage of the adapter suite:** the assurance root CI job runs
  the root `tests/` tree only; the `integrations/langgraph-adapter` suite is
  analysed by Sonar and run from the adapter directory (with its own
  `conftest.py` path bootstrap) rather than by the root pytest job. This
  document states that split rather than implying a green root job covers the
  adapter suite.
- **B6. Version-span co-installation:** the P2a family (pydantic-ai,
  google-adk) and the crewai family cannot co-install at their verified
  spans; one framework family per environment is the practical deployment
  rule, enforced by CI layout rather than by resolver constraints.
- **B7. Audit-source actors:** no connector or normaliser row invents
  principals; unknown actors stay explicitly unknown with a machine-readable
  reason.

## 7. Honest NOT-tested registry

Rows that do NOT carry an explicit identity, request-integrity, replay or
error-handling contract test set, named so that no coverage is implied:

- **A4 (oaa-epaec)** and **A5 (oaa-audit-sources)**: packaging and
  normalisation suites exist, but there is no identity/replay contract set at
  a runtime seam because there is no runtime seam to test.
- **A6 (SIEM webhook)**: retry, dead-letter, dedupe and secret-freedom
  contracts exist; there is no identity contract because the exporter holds
  no acting identity.
- **R1 to R8 (OSS in-process handlers)**: per-framework suites assert the
  allow/deny/receipt behaviour at each seam (including unattributed-call
  denies for crewai and pydantic-ai), but there is no cross-handler replay
  contract suite; replay authority rests with the receipts and the gate, and
  replay contracts are bound only for the assurance enforcement adapter
  (section 3) and the evidence plane (A2's binding tests).
- **A7 / section 5 targets**: no tests can exist for integrations that are
  not shipped.
