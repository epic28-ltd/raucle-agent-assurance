# instrumentation — PRIV-01 redaction controls

SDK-side span-attribute redaction plus collector-side defence-in-depth for
Open Agent Assurance (story PRIV-01: sensitive content must not persist in
the normal trace store).

## Layout

- `src/oaa_instrumentation/redaction.py` — the deterministic redaction core:
  versioned pattern config (`config/redaction.yaml`, `config_version: 1`)
  matching AWS access keys, bearer tokens, JWTs, private-key PEM blocks,
  credential key/value pairings and emails; plus a high-entropy heuristic
  (Shannon entropy per char ≥ 4.0, length ≥ 20, base64-ish charset only).
  Matching values are replaced with `[REDACTED:<class>|len=<n>]` — the class
  tag and the original length, nothing else. Keys matching `oaa.metadata.*`
  pass through unredacted (the metadata-only namespace).
- `src/oaa_instrumentation/otel_processor.py` — OTel exporter wrappers:
  `RedactingSpanExporter` (scrub at the SDK, before export) and
  `QuarantiningSpanExporter` (re-scan the batch immediately before export;
  flagged spans are held back and counted — violations are counted, never
  logged with the secret).
- `config/redaction.yaml` — the versioned pattern config.

## Guarantees

- Deterministic: same input batch → same scrubbed output and same violation
  set; no wall-clock, no RNG.
- Violation records carry `pattern_id`, `privacy_class`, `attr_key` and the
  matched length only — never the matched value.
- A content-hash of a secret is NOT anonymisation; only the length prefix is
  retained.
- Detection is pattern- plus entropy-based, not semantic (see
  `docs/spikes/PRIV-01-findings.md` for proven limits).