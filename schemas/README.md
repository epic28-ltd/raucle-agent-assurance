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
