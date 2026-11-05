# Agent assurance for leaders

Audience: executives and accountable owners deciding whether an agentic
deployment carries enough assurance to go live. Everything named below
exists in this repository today; where a capability is only planned, it is
marked planned and tracked in the overnight sprint backlog.

## The claim in one sentence

We can reconstruct, from receipts, what an agent did, what its gate allowed
or denied, and whether the evidence itself was tampered with —
reconstructability, not log completeness.

## What is proven today

- Exportable audit packs with offline verification and deliberate-tamper
  detection turning RED: `docs/audit-pack.md` describes the pack;
  `scripts/build_audit_pack.py` builds it from the evidence store and
  `tools/verifier/verify_pack.py` verifies it, answering GREEN or RED with
  named failure lines (`tests/verifier/test_verify_pack_tamper.py` pins the
  tamper behaviour).
- A threat model that maps ten threat scenarios to named controls and
  records residual risks in writing: `docs/threat-model/threat-model-v0.md`.
- An architecture for two evidence planes trusted at the hash level, with
  the rule that `valid` is never inferred from missing data:
  `docs/adr/0001-trust-model-and-evidence-plane.md`.
- A privacy posture of metadata-only telemetry by default, tested rather
  than promised (`tests/security/test_redaction.py`); the AgentRunRecord
  schema makes prompt/response content, raw receipt bytes and credentials
  structurally unrepresentable (`schemas/agent_run_record.schema.json`).
- A regression red gate on the agent side, run end to end in the recorded
  demo (`docs/demo/demo-run-4nov.md`).

## What is honest about the gaps

- Backend outage behaviour degrades: the P3 probe
  (`examples/reference-agent/p3_outage.py`) showed a stock OTLP exporter
  silently dropping spans on connection refused; bounded retry is a
  requirement, not yet shipped. Planned, tracked in the overnight sprint
  backlog.
- The invariant section of the delta report is heuristic, not a proof,
  where the SAT solver is not installed (z3 optional dependency).
- ADRs carry import status, not Accepted: review is pending, see
  `docs/README.md`.

## Decisions this evidence supports

Go/no-go on an agentic release relies on the four-question loop: what did
the agent reach for, what did the gate decide, is the evidence chain intact,
what residual risk stays with a named owner. Release comparison against a
baseline (classification of new versus persistent failures) is planned and
tracked in the overnight sprint backlog.

## Verify instead of trust

You do not have to take the claims above on faith. The auditor quickstart
(`docs/auditor-quickstart.md`) walks the verification path from an exported
pack to an independent GREEN/RED verdict, and the docs-alignment check used
to police this very document is `scripts/check_docs_alignment.py`.
