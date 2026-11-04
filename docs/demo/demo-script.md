# Raucle Agent Assurance — alpha demo script

Audience: technical buyer or reviewer. Runtime: about 10 minutes if walking each step, under 2 minutes when pre-staged.
Everything runs locally; nothing leaves the machine. Repo: `~/Projects/open-agent-assurance`.

## 0. Pre-stage (before the demo starts)

```bash
cd ~/Projects/open-agent-assurance
.venv/bin/uvicorn oaa_investigation_ui.app:app --port 3410 --app-dir services/investigation-ui/src &
# evidence + demo data live in services/investigation-ui/src/oaa_investigation_ui/demo_data
```

Keep handy:
- UI: http://127.0.0.1:3410
- Langfuse (spike stack): http://127.0.0.1:3301
- Repo: 12 commits, 244 tests passing

## Act 1 — the gate produced signed evidence (Trust)

```bash
# Show the canonical, unmutated evidence store (obs01 real run: one allow, one deny)
cat ~/Projects/oaa-spike-4nov/obs01/receipts.jsonl | python3 -m json.tool
# sha256 of the file at demo time — matches the spike's recorded immutability proof
sha256sum ~/Projects/oaa-spike-4nov/obs01/receipts.jsonl
```

Say: "The agent's tool calls went through the gate. Every decision — allowed or denied — produced a signed receipt. These bytes are the canonical evidence and they are never modified again."

## Act 2 — correlate, never mutate (Assurance core)

In the UI (http://127.0.0.1:3410):
1. **Runs list**: show the run, its spans, and correlation states per tool call.
2. Click the trace with the **deny** receipt → trace drilldown: each privileged span shows `receipt_hash` + verification state + correlation state.
3. Point out the **amber `unknown`/`receipt missing` badges** as deliberate, first-class states — "the system can say what it did NOT see, which is exactly what record-only products cannot do."

## Act 3 — independent verification in front of them

Evidence panel → **Verify offline**:
- Verifier output prints: `valid: true`, verifier pin `raucle 0.23.5 (git 63edacd)`, full checks list.
- Say: "Verification runs offline over the canonical bytes, with trust roots we archive through rotation. No server needed, no vendor in the path. That is the sovereign trust boundary."
- If a questioner asks "what if you lie?": show the invalid fixture — byte-tampered receipts fail with `receipt_hash mismatch — record tampered`.

## Act 4 — coverage and bypass (the claim others cannot make)

- Findings panel: `SEC-002` unsupported-schema finding + one **suppressed with a documented reason** (suppression keeps, never hides).
- Say: "Bypass detection compares the gate's receipts with independent tool-side audits. Traces alone never prove or disprove a bypass — a compromised agent can forge traces, but it cannot forge a receipt. Detection strength scales with credential custody."

## Act 5 — the honest report (differentiator against the market's compliance-UI)

```bash
open ops/assurance/example-report.md
```

Point at the mandatory limits section: scope (gated paths only), per-tool coverage defaulting to `unverified`, and the line that a receipt or report does not establish legal or regulatory compliance. "Every compliance claim in this report is structurally blocked by a test. Contrast: the category leader's dashboard shows 'EU AI Act compliance' as a widget."

## Act 6 — operational reality (optional, if asked)

- `ops/runbook.md`: proven backup/restore round-trip (hashes), restart recovery, upgrade checklist.
- Load smoke: 1,201 runs / ~24k spans, no measurable producer overhead (smoke, not benchmark).
- Export path: `EXP-01` SIEM webhook with deterministic event ids and dead-letter replay.

## Closing line

"Raucle Agent Trust proves what was allowed to run. Raucle Agent Assurance detects what ran outside it. Raucle Agent Red, next wave, finds what gets through — and because it runs under the same gate, its own attacks are receipted: a pentest report your auditor can verify."