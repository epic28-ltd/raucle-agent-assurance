# DISC-02 findings — raucle receipt/verifier integration spike (EPIC K)

Date: 2026-11-04 · Repo: https://github.com/epic28-ltd/raucle · Local clone: ~/Projects/raucle
Scratch/demo: ~/Projects/oaa-spike-4nov/ (nothing committed, nothing external contacted)

## 1. Version pinned

- **Latest release tag: v0.23.5** at commit `63edacd5332509694e12873badc15da8a3708243`
- **HEAD of main pinned for inspection: `2013a686a78610435eb27b9aed910c808808b4a2`**
  ("docs: README capability wave…", 2026-10-30) = `v0.23.5-18-g2013a68`, i.e. 18 commits after the release tag.
- `pyproject.toml:7` → `version = "0.23.5"`. Demo and code reading were run against this pinned HEAD.

## 2. Public / API surface for receipt verification

All importable (`import raucle`; package dir `raucle/`, flat layout):

| Module | Class | Key signatures |
|---|---|---|
| `raucle.provenance` | `ProvenanceReceipt` | `.sign(identity, hybrid=None) -> str (jws)`, `.to_jws() -> str`, `from_jws(jws, *, strict=False, validate_structure=True) -> ProvenanceReceipt` (provenance.py:738/774/815) |
| `raucle.provenance` | `ProvenanceVerifier` | `__init__(public_keys: dict[kid→PEM bytes], capabilities=None, pq_public_keys=None, require_pq=False)`; `.verify_chain(path) -> VerificationReport`; `.trace(receipt_hash, path)` (provenance.py:1417/1449/2005) |
| `raucle.provenance` | `AgentIdentity`, `CapabilityStatement` | `AgentIdentity.generate(...)`; CapabilityStatement gates `permits_tool/permits_model` |
| `raucle.provenance` | `ProvenanceLogger` | `record_tool_call(*, parents, tool, input_args, output, extra_taint=None) -> hash`; `_check_tool_permission` raises `PermissionError` for non-permitted tools (producer-side, cooperative) |
| `raucle.verdicts` | `VerdictSigner` / `VerdictVerifier` | scanner-verdict receipts: `issue(*, input_text, verdict, confidence, ruleset_hash, model_version="", tenant=None, extra=None)`; `verify(receipt, *, expected_input=None, expected_ruleset_hash=None, max_age_seconds=None)` |
| `raucle.gateway` | `RaucleGateway` | `check_tool_call(tool, args, agent_id="", source="", destination="", trace_id="", approval_id="", ...) -> dict` (gateway.py:1396); emits signed gate receipts for allow AND deny via `_emit_gate_receipt` (gateway.py:1023) / `_sign_and_store_receipt` (gateway.py:931) |
| `raucle.audit` | `HashChainSink`, `AuditVerifier` | hash-chained audit records (see §3) |
| `raucle.receipt_store` | `SegmentedReceiptStore` | append-only JSONL chain-of-record storage |

Trust-root configuration (importable, not server-bound):
- Verifier takes **`public_keys: dict[key_id -> PEM Ed25519 public key]`** in constructor. `key_id` = first 16 hex chars of sha256(PEM) for signer classes (`verdicts.py` ~line 148).
- Capability conformance is verifier-side when `capabilities: dict[agent_key_id -> CapabilityStatement]` is supplied; statements are self-signed in OSS mode, issuer-signed in commercial mode (provenance.py:620-638).
- Gateway signs with a local Ed25519 key (`signer_backend="local"`, key file 0600); `gw.gate_identity.key_id` + `gw.gate_identity.public_key_pem()` are the wiring to hand to the verifier ("public for verification wiring", gateway.py:1078).
- Optional PQ hybrid (`raucle.pq1`, Ed25519+ML-DSA-65, `quantum_mode="strict"`) — no downgrade path.

**Yes, verification is a fully importable interface** — the demo imports only `GatewayConfig`, `RaucleGateway`, `ProvenanceVerifier`.

## 3. Receipt schema variants — both mechanisms exist

1. **Signed receipts (JWS, preferred for evidence export)** — three families:
   - `raucle.provenance` provenance receipts: compact JWS, `alg=EdDSA`, `typ=raucle-receipt/v1` (via `_RECEIPT_TYP`), `crit=["raucle/v1"]`, `raucle/v1: "provenance"` (gateway) or header `typ` for pure provenance. Envelope on disk is minimal: `{"receipt_hash", "jws"}` per JSONL line; **verifier rejects any other envelope field** (provenance.py:1501-1505, `raucle.registry.unknown_envelope_fields`).
   - `raucle.verdicts` scanner-verdict receipts: detached JWS `raucle/v1: "verdict"`, payload `{iss, iat, input_hash, verdict, confidence, ruleset_hash, model_version, tenant?, extra?}`.
   - Gate decision receipts: a `guardrail_scan`-shaped provenance receipt with an **`x_gate` extension inside the signed payload** binding the full decision context; verifier re-checks extension families (`_verify_receipt_extensions`, provenance.py:1645-1663; v1.1 delegation, v1.2 task-intent docs in docs/spec/provenance/v1/).
2. **Hash-chained audit records** — `raucle.audit.HashChainSink` / `AuditVerifier`: append-only JSONL, genesis `chain_meta` header, each line carries canonical event hash + previous hash, optional Ed25519 signed checkpoints; tamper-evident without a signer, attributed with one. `raucle.receipt_store.SegmentedReceiptStore` + `raucle.receipt_index.sqlite` (indexed columns include `trace_id`) sit on top for receipts v1.1 ledger.

## 4. Correlation hooks — code-visible

- `trace_id` is a **first-class signed field**:
  - HTTP layer: `X-Trace-Id` header (`gateway_app.py:332,252` — `trace_id = x_trace_id or uuid4().hex`).
  - Gate API: `check_tool_call(..., trace_id="")` parameter.
  - It is written into the **signed** `x_gate` block (gateway.py:1040) and indexed (`receipt_index.py:84-98`, `idx_receipts_trace`, query/filter by trace_id in the admin UI, `gateway_app.py:1767`).
  - Test `tests/test_gate_receipts.py::test_trace_id_threads_receipts` confirms cross-receipt threading.
- Other correlation carriers: `approval_id` (approvals.py, `trace_id` field there too), receipts v1.1 delegated-authority `authorization` blocks with `token_id` "for correlation", task-intent binding (v1.2).
- Limits: the `x_gate` field set is fixed in code — free-form per-call metadata on a receipt would need a new `x_` extension following the established convention (`x_args_commitment` precedent, docs/spec/provenance/v1/conformance-reverification.md:59) — i.e. upstream spec/code change for arbitrary metadata, but **run-ID correlation itself is already native**.

## 5. Canonicalisation & immutability

- Signing input is `b64url(JCS(header)) + "." + b64url(JCS(payload))`, signature Ed25519 appended: exactly those bytes + `.` + b64url(sig) = **the canonical artefact** (provenance.py:761-772).
- JCS enforced on re-parse in strict mode: `\_canonical_json(header_obj) != header_bytes` rejects non-canonical encodings, duplicate object keys rejected — no byte-malleable re-encoding of the same logical content (provenance.py:799-812).
- `receipt_hash = "sha256:" + sha256(compact JWS ascii)` (provenance.py:771; also `from_jws:885`), recomputed by the verifier from the JWS bytes — any byte mutation breaks the hash; `parents` and `taint` are key-sorted canonicalisations (`_utf16_key` from `raucle/_canon.py`, UTF-16le ordering per RFC 8785).
- Immutability is by construction: append-only sinks, no API mutates an emitted receipt; store is `{receipt_hash, jws}` minimal envelopes only.

## 6. Demo transcript (raucle's own verifier, mocked tools, no external calls)

Run: `~/Projects/raucle/.venv/bin/python disc02_demo.py` (script: `disc02_demo.py`). Key output:

```
ALLOW  decision: allow | reason: ok | receipt_id: sha256:21a1bcf7ee154c04…68499
DENY   decision: deny | reason: constraint violated: path contains '/etc/passwd' which is not in allowed_values | receipt_id: sha256:c40a26dec0f42d26…b7bf94fe

ProvenanceVerifier.verify_chain -> {
  "valid": true, "receipt_count": 2,
  "signature_failures": 0, "parent_link_failures": 0,
  "taint_monotonicity_failures": 0, "capability_violations": 0,
  "unauthorised_sanitisations": 0, "tampered_receipts": [], "errors": []
}

receipt sha256:21a1bcf7ee154… verdict='allow' x_gate.trace_id='demo-trace-cafe01' tool='read_file'
receipt sha256:c40a26dec0f42… verdict='deny'  x_gate.trace_id='demo-trace-cafe01' tool='write_file'

trace-side record written -> trace_record.json
receipt bytes unchanged after trace-side attach: True
re-verify after correlation attach: True
```

Verbatim envelope bytes (one JSONL line each, 1240/1343 bytes) were captured by re-reading `receipts.jsonl` as **raw bytes** and sha256-ing before and after writing the trace-side record (`trace_record.json` keyed by `trace_id` → receipt hashes); hashes unchanged → receipt bytes were never touched. Correlation lives entirely trace-side or in the already-signed `x_gate.trace_id` at issuance.

## 7. Verdict

**Correlation achievable without upstream change: YES (for run-ID correlation); PARTIAL only for arbitrary per-event metadata.**

- Correlating tool calls/decisions to a run/session: **native** — pass `trace_id` (API param or `X-Trace-Id` header); it is signed into each gate receipt and indexed for query. No repo change needed.
- Gate receipts for allow AND deny are signed offline-verifiable provenance receipts — the evidence-index integration (Langfuse-first, backend-agnostic) can store verbatim `{receipt_hash, jws}` envelopes and verify with `ProvenanceVerifier` using the gateway's public key.
- Gaps (only if broader correlation metadata is wanted per receipt):
  1. `x_gate` field set is fixed; arbitrary metadata requires a new registered `x_` extension (code + spec amendment, `x_args_commitment` precedent).
  2. Producer-side tool permission check (`ProvenanceLogger`) is cooperative only — evidence index should not rely on it (verifier-side capability check exists when statements supplied).
  3. Free-form provenance receipts via `ProvenanceLogger.record_tool_call` have **no trace_id field at all** — correlation there must ride `parents`/hashes trace-side, whereas the Gateway path is the one to use for the OAA companion.

No-go blockers found: none. Spike supports go for EPIC K.