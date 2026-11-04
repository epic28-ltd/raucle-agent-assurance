# Open Agent Assurance

A companion to [raucle](https://github.com/craigamcw/raucle) that layers
workflow correlation, coverage analytics and assurance reporting on top of a
policy-enforcement gate that mints independently verifiable evidence (signed
receipts). The companion correlates the gate's signed receipts with agent
OpenTelemetry traces — it does **not** duplicate gating, receipts,
counterfactuals or compliance packs.

**Status: alpha, in progress.** No CI claims are made yet; see the CHANGELOG
and docs/README.md for what exists and what is planned.

## Invariants (binding; full rationale in docs/adr/0001)

1. Never mutate canonical evidence — the gate's `{receipt_hash, jws}` JSONL
   bytes are stored verbatim, sha-verified in and out; derived state lives in
   a separate index only.
2. `valid` is never inferred from missing data — unknown, not_applicable,
   pending, unavailable and zero stay schema-distinguishable.
3. The companion is never the enforcement authority — its failure or absence
   must not change the gate's decisions.
4. Correlation is a hint, not authentication — producers authenticate;
   the signed `x_gate.trace_id` is authoritative where present.
5. Versioned trust roots — retired keys are archived, never deleted;
   verification selects roots by key_id and event time.
6. Conformance fixtures are the portability mechanism — the versioned fixture
   corpus (tests/conformance) covers every verification state.
7. Metadata-only telemetry by default; redaction is tested, not promised.
8. Telemetry loss must be visible, not silent — bounded-retry exporting with
   explicit loss counters (demonstrated against the stock OTLP exporter in
   docs/spikes/OBS-01-findings.md).

## Layout

- `docs/adr/` — architecture decision records (0001 trust model / evidence
  plane, 0002 event contract, 0003 backend adapter)
- `docs/threat-model/` — threat model v0
- `docs/spikes/` — imported discovery/evidence/observability spike findings
  (historical records, not product docs)
- `schemas/` — event-contract schemas (planned)
- `packages/raucle-adapter/` — evidence-plane core: verbatim store, versioned
  trust-root registry, fixture classification; conformance fixture generator
- `packages/instrumentation/` — `oaa.*` OTel instrumentation (planned)
- `services/evidence-index/`, `services/correlation/` — planned services
- `integrations/backends/`, `integrations/siem/` — trace/SIEM integrations
  (planned)
- `deploy/compose/` — self-hosted Langfuse v4.74.0 compose stack
- `examples/reference-agent/` — the OBS-01 reference agent + probe scripts
- `tests/conformance/` — fixture corpus + evidence-plane tests (raucle-free
  set runs everywhere; signature tests skip without raucle)
- `tests/security/`, `tests/load/` — planned (OAA SEC-001..008, load)

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install pytest ruff
PYTHONPATH=packages/raucle-adapter/src pytest tests/ -rs
ruff format --check . && ruff check .
```

See CONTRIBUTING.md and packages/raucle-adapter/README.md (raucle pin).

## Licensing

Apache-2.0 (see LICENSE). Spike findings docs are project records under the
same licence. Langfuse and its licences are described in NOTICE.