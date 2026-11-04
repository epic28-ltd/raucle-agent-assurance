# PRIV-01 findings — seeded-secret proof and redaction controls

**Story:** PRIV-01 "Prevent sensitive content persistence — seeded secrets
absent from normal trace store" (plan P0).
**Date:** 4 Nov 2026. **Where:** local-only repo run with the live self-hosted
Langfuse v4.74.0 stack (compose `~/Projects/oaa-spike-4nov/obs01/docker-compose.yml`,
web UI at `127.0.0.1:3301`). **No external network was used** — all OTLP
exports and API readbacks stayed on the local stack.

**Verdict:** PASS (P0 acceptance demonstrated live, both directions).

## What was proven live

1. **Counterfactual (a) — the harness catches leakage.** A deliberately
   leaky fixture trace (raw seeded secrets as span attributes on one agent
   span) was emitted via the SDK's plain OTLP path to the LOCAL stack. The
   live API readback (trace detail + observations text) contained **8 of 8
   sensitive seeded values verbatim**, including inside the LLM message
   echo. Without redaction, secrets persist in the normal trace store —
   confirmed by readback, not by assumption.
2. **Controlled run (b) — seeds absent.** The same fixture, same seeds,
   same attribute keys, with `RedactingSpanExporter` (SDK scrub before
   export) chained into `QuarantiningSpanExporter` (collector re-scan
   immediately before export) → OTLP:
   - live readback: **0/8** sensitive seeds present; the allowlisted
     `oaa.metadata.*` value still travels unchanged (passthrough held);
     `[REDACTED:<class>|len=<n>]` tokens present in the stored metadata
     (24 in the recorded run);
   - collector scan over the post-scrub export batch: **0 violations**,
     **0 quarantined spans**.
   Both runs are reproducible via
   `OAA_PRIV01_LF_ENV_FILE=… pytest tests/security/test_priv01_live.py`.
3. **Collector quarantine behaviour, offline**: scanning the RAW leaky
   batch yields one violation per seeded class (≥ 8) and the quarantine
   selection holds back exactly the flagged spans while clean spans pass —
   never logging matched values (unit-tested: no seed value appears in any
   violation/report serialisation).

## Config shape

`packages/instrumentation/config/redaction.yaml`, `config_version: 1`:

- `allowlist: ["oaa.metadata.*"]` — key globs exempt from redaction
  (metadata-only namespace; the ONLY place free-form values may travel).
- `patterns[]` — `{id, class, match}` regexes: aws_access_key_id
  (AKIA/ASIA/ABIA/ACCA + 16), bearer_token, jwt, private_key_pem
  (whole BEGIN…END block as one unit), credential_kv (key/value pairing),
  email.
- `entropy_heuristic` — `{enabled, min_length: 20, threshold_bits_per_char:
  4.0, base64_charset_only: true, class: high_entropy}`: Shannon entropy per
  char, deterministic; values that already matched a pattern are not
  re-classified.
- Replacement token: `[REDACTED:<class>|len=<n>]` — class tag plus original
  length only. Violation records carry `pattern_id`, `privacy_class`,
  `attr_key`, `matched_length`; the matched value is never retained anywhere
  (unit-asserted over every report serialisation).

## Determinism

Same attribute batch → same scrubbed values and same violation set; no RNG,
no wall-clock anywhere in the code path. The seeded secrets themselves are
generated with a pinned RNG (`tests/security/fixtures/seeds/gen_seeds.py`)
so regenerating is a no-op; the committed `seeds.json` is stable.

## Limits (declared, not hidden)

- **Detection is pattern + entropy, not semantic.** A secret that matches no
  pattern, is prose-spread, or is entropy-flat can pass. The entropy layer
  only catches opaque blobs (charset gate excludes dash/structured ids and
  prose; per-char entropy ≥ 4.0 and ≥ 20 chars). Knife-edge: a mixed
  40-hex string sits at 3.95 (below threshold) while a full-alphabet
  uniform hex string is exactly 4.0 — the unit tests pin both bounds.
- **Dash-carrying secrets can evade the entropy layer** (charset gate);
  the pattern layer is the primary control — mitigation is pattern
  coverage, not threshold tuning.
- **Encrypted-looking blobs caveat**: ciphertext is indistinguishable from
  high-entropy secrets, so it WILL be redacted (false positive by design);
  metadata-only default is the real control, the redaction gate is
  defence in depth.
- **Content-hash is NOT anonymisation** (plan §8): a hash of a secret is
  still a derivative of the secret; only the value length is retained in
  the replacement token, no hashes.
- **Redaction is substring/attribute-level, not semantic over JSON
  structure**: nested JSON inside one attribute is treated as one string
  (patterns still match inside it).
- The readback proof asserts on trace-detail + observations text; Langfuse
  search endpoint does not index arbitrary attribute values, so "absent"
  means absent from full text of the trace's stored payloads, not absent
  from the index.
- Collector scan operates on attribute maps at export time; a hostile
  exporter could bypass the wrapper — the real collector enforces this in
 -process in production (same function, same config).

## What remains for full PRIV coverage

- Pattern-coverage growth driven by real leakage incidents (e.g. Slack
  tokens, Google API keys, `sk-` LLM keys — generic credential_kv catches
  some but not all shapes).
- A canonical escape-encoder pass (URL- / base64-encoded secrets are not
  de-coded before matching today).
- Quarantine retention semantics (where held-back spans go, TTL, review
  UI) — currently counted + dropped.
- Coverage story wiring: redaction config version + config hash should feed
  the assurance report (per-application overrides).
- `oaa.content_class` tagging discipline: an explicit
  metadata-only-vs-content enforcement at span-creation time (currently the
  SDK redacts whatever content arrives — the policy layer should refuse
  content classes outright rather than relying on scrubbing).