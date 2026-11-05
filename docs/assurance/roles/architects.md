# Agent assurance for architects

Audience: architects designing or reviewing agentic systems against the
Open Agent Assurance model. Everything referenced exists in this repository
today; planned work is marked planned and tracked in the overnight sprint
backlog.

## The two-plane shape

Read `docs/adr/0001-trust-model-and-evidence-plane.md` first: a telemetry
plane and an evidence plane, with versioned trust roots, historic
verification after key rotation, and correlation kept out of the authority
path. `docs/adr/0002-event-contract.md` defines the canonical model (eight
entities) with a dual-taxonomy adapter for OTel GenAI plus OpenInference.
`docs/adr/0003-backend-adapter.md` covers the Langfuse-first adapter and the
three de-risking probes that had to pass before UI work.

Rules that constrain any design built on this:

1. The companion never becomes the authority for tool permissions.
2. Canonical receipt bytes are preserved verbatim; derived state lives in
   the index only.
3. `valid` is never inferred from missing data; unknown, not-applicable and
   zero stay distinct.
4. Producers authenticate; trust-root registry schema is planned, tracked in
   the overnight sprint backlog.

Where these rules are exercised:

- `examples/reference-agent/reference_agent.py` — reference agent with
  metadata-only `oaa.*` attributes; `tests/security/test_redaction.py`
  pins the redaction behaviour.
- `docs/adr/0004-bypass-detection.md` and
  `docs/adr/0005-gate-identity-correlation.md` — the bypass and correlation
  authenticity decisions.

## Run-record contract

`schemas/agent_run_record.schema.json` is the privacy-filtered per-run
record: receipts, capability references, policy proof ids, governance
events, usage metrics — nothing else is representable. Fixtures generate
deterministically from the committed demo data with
`tools/run_records/generate_fixtures.py`, and
`tests/conformance/test_agent_run_record.py` covers both schema validation
and the refusal to emit content-bearing payloads. If a future consumer needs
more fields, extend the schema closed-set first: additionalProperties stays
false everywhere.

## Boundaries and threat model

`docs/threat-model/threat-model-v0.md` maps ten threat scenarios across six
trust boundaries to controls with residual risks accepted in writing. When
proposing a change, name the boundary it touches and the control that keeps
its scenario RED.

## What is not settled

- Invariant checking degrades to heuristics without a SAT solver; treat the
  delta-report invariant section as advisory in that mode.
- ADRs are pending review before status upgrade, `docs/README.md`.
- Release-baseline comparison tooling is planned, tracked in the overnight
  sprint backlog.

The alignment script that keeps these references honest:
`scripts/check_docs_alignment.py` (run after edits; see the engineers page).
