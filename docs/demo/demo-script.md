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
- Console (Raucle Console, with the Red page): http://127.0.0.1:3412
- Assurance findings board: http://127.0.0.1:3411
- Red runner: 127.0.0.1:3415 and the demo named gate on 127.0.0.1:3416
- Repo: 12 commits, 244 tests passing

Runner and demo gate, if down (before Act 5):

```bash
cd ~/Projects/raucle-agent-red
.venv/bin/python scripts/demo_gate.py &                     # demo-billing-agent gate, :3416
env RED_RUNNER_PORT=3415 .venv/bin/uvicorn red.runner.service:app --host 127.0.0.1 --port 3415 &
```

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

## Act 5 — the live red run (Console Red page)

Open the console (http://127.0.0.1:3412) → **Red** page.

1. **Target selector**: pick the named gate `demo-billing-agent` (registered in the
   runner's local `gates.yaml`, loopback 3416, no spawn; the runner probes the
   gate over HTTP like any deployed gate). Alternatively pick `demo gateway`
   (the pinned gateway, spawned per run).
2. **Preset**: Quick pass (see "what if asked" below for Deep sweep).
3. **Press Start**, then narrate while the counters tick:
   - the attempts / allow / deny counters and the receipts minted line count up;
     every attack attempt goes through a red identity gate first, so the red run
     itself is receipted (dogfooding);
   - the state chip goes grey (idle) → amber (running) → green (complete);
   - the current suite line walks policy fuzz → gateway HTTP → mcp → tamper →
     forge → lease.
   - Real figures to quote (measured 4 November):
     quick about 90 attempts, deep about 500 attempts / 18 findings, both
     finished in seconds; see `red docs/deep-sweep-timing.md` in
     `~/Projects/raucle-agent-red`. Nothing here hangs around: no presenter
     dead air.
4. When the run completes, press **Ingest findings into Assurance**, then show the
   ingested-findings summary. The intake is idempotent by finding_id: re-running
   ingest replaces, never duplicates.
5. Show **RED-017 on the board** (http://127.0.0.1:3411): the lease-expiry window
   finding is now an ingested row on the Assurance board next to the synthetic
   SEC findings: pentest evidence with the same provenance as everything else.
6. **Stop** button if needed: graceful abort, the state chip goes red
   (aborted); the run finishes its current suite and keeps the rows it has.

### What if asked

- **"The console says the runner is offline."** The Red page shows an honest
  state line and never guesses: the console has no runner in its own process,
  it proxies to 127.0.0.1:3415 and degrades explicitly. `503 red runner
  offline` with nothing invented in place of status. Fix is the pre-stage
  command above (start the runner, wait for idle, press Start again).
- **"Deep or quick?"** Both finish inside the demo window (seconds: deep
  sweeps about 500 receipted attempts and lands 18 findings; quick caps at a
  fixed slice, about 90 attempts). Deep is the honest default for the demo
  because it costs nothing live.
- **"Why are there denies? Isn't that a failure?"** No. Each attempt is a red
  attempt receipt plus the target gate's own decision. A deny is the target
  gate doing exactly its job against an attack probe. What the run reports is
  the set of attempts that got PAST the gate against their author intent
  (allow-beyond-intent, RED-003 and friends) plus parity/tamper gaps. A
  healthy deny count is the receipt that the boundary held; the evidence
  exists whether the answer was allow or deny.

## Act 6 — the honest report (differentiator against the market's compliance-UI)

```bash
open ops/assurance/example-report.md
```

Point at the mandatory limits section: scope (gated paths only), per-tool coverage defaulting to `unverified`, and the line that a receipt or report does not establish legal or regulatory compliance. "Every compliance claim in this report is structurally blocked by a test. Contrast: the category leader's dashboard shows 'EU AI Act compliance' as a widget."

## Act 7 — operational reality (optional, if asked)

- `ops/runbook.md`: proven backup/restore round-trip (hashes), restart recovery, upgrade checklist.
- Load smoke: 1,201 runs / ~24k spans, no measurable producer overhead (smoke, not benchmark).
- Export path: `EXP-01` SIEM webhook with deterministic event ids and dead-letter replay.

## Closing line

"Raucle Agent Trust proves what was allowed to run. Raucle Agent Assurance detects what ran outside it. Raucle Agent Red, next wave, finds what gets through — and because it runs under the same gate, its own attacks are receipted: a pentest report your auditor can verify."