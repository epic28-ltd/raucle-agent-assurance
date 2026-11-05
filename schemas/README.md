# schemas

Planned Open Agent Assurance build-out. See docs/README.md and docs/adr/ for
status.

## Contents

- `rules-config.schema.json` — gate rules configuration schema.
- `agent_run_record.schema.json` — AgentRunRecord (Sprint backlog OV-8):
  privacy-filtered run record per agent run, carrying receipts (metadata
  fields only), capability references, policy proof ids, governance events
  and usage metrics. No prompt or completion content, raw receipt bytes
  (`jws`), credentials or end-user identifiers are representable. Unknown
  stays distinct: `decision: "unknown"` is a first-class value, never
  inferred into allow or deny.

- `agent_assurance_packet.schema.json` — Agent Assurance Packet (OV-1):
  deterministic, tamper-checked packet compiled from a receipt-chain
  evidence store; ids, digests and counts only, never receipt denial
  reasons. Optional `packet_pq_signature` (OV-22) is an ML-DSA-65
  signature over the packet digest, added after the digest stamp. The
  packet's ML-DSA field carries its own public key, so revalidation
  proves post-quantum tamper-evidence of content, NOT authentication to
  a known signer.

## Fixture generation

`tools/run_records/generate_fixtures.py` builds AgentRunRecord fixtures
deterministically from the committed demo data
(`services/investigation-ui/demo_data/runs.json` +
`synthetic_receipt_index.jsonl`), with a refuse-to-emit privacy scan.
Committed fixtures: `services/investigation-ui/demo_data/agent_run_records.json`.
Tests: `tests/conformance/test_agent_run_record.py`.

Regenerate with the project venv:

```bash
.venv/bin/python tools/run_records/generate_fixtures.py \
  --out services/investigation-ui/demo_data/agent_run_records.json
```
