# examples/reference-agent

The OBS-01 vertical-slice reference agent and its de-risking probe scripts,
imported from the 4 Nov spike.

- `reference_agent.py` — synthetic OTel trace (AGENT root → LLM stub,
  RETRIEVER, TOOL) using OpenInference span kinds and the `oaa.*` attribute
  namespace. Metadata-only by default: `oaa.content_class` carries only a
  class, never a raw secret.
- `verify_p1.py` — P1 probe: attribute round-trip fidelity (diffs
  originals.json against Langfuse readback).
- `p2_p5_correlation.py` — P2/P5 probes: score attachment + raucle
  receipt-to-trace correlation (allow AND deny), receipts stored verbatim,
  sha256-checked before/after attach.
- `p3_outage.py` — P3 probe: backend-outage behaviour (stock OTLP exporter
  silently drops spans on connection refused → bounded-retry requirement).
- `originals.json`, `p1_report.json`, `p2_report.json`, `p3_report.json`,
  `p5_receipts_report.json` — outputs from the recorded spike run.

## Running

Requires the local Langfuse stack (deploy/compose/README.md) up on
127.0.0.1:3301 and a project with OTLP API keys in a local `obs.env`
(git-ignored; variable names LANGFUSE_INIT_PROJECT_PUBLIC_KEY /
LANGFUSE_INIT_PROJECT_SECRET_KEY):

```bash
python3 -m pip install opentelemetry-sdk opentelemetry-exporter-otlp
python reference_agent.py
python verify_p1.py && python p2_p5_correlation.py && python p3_outage.py
```

`sample-receipts.jsonl` is a truncated sample receipt envelope pair from the
recorded run (display shorthand, not byte-complete — see findings).