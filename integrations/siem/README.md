# siem

EXP-01 — generic SIEM webhook exporter (Apache-2.0).

- `webhook.py`: stable outbound event envelope v1 (deterministic UUIDv5
  `event_id`), no secrets / raw content / payloads, stdlib HTTP POST with
  bounded retry + backoff, dead-letter JSONL sink, persisted `event_id`
  dedup state (at-least-once transport, receiver merges idempotently by
  `event_id` — see `IdempotentCollector`).
- `config/webhook.yaml` + `config/webhook-config.schema.json`: versioned
  config; endpoint URL is env/config only (`OAA_SIEM_WEBHOOK_URL` overrides,
  `https` enforced by default). No credentials here or in the envelope.
- Tests: `tests/integrations-siem/test_webhook.py` (offline, in-process
  dummy HTTP server).
- Design, guarantees, limits and the envelope→CEF/OTel mapping table:
  `docs/spikes/EXP-01-findings.md`.