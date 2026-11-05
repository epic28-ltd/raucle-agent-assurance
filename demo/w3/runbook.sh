#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# W3 hero demo runbook (Sprint 1 P1.D3 + P1.9a). One clean run-through, all
# beats local, loopback only, nothing leaves the machine.
#
# Home: ~/Projects/open-agent-assurance/demo/w3 (this file and the transcript).
#
# Framing line, say it out loud in the session:
#   "reconstructability, not log completeness"
#
# Beats:
#   1. F7 hero    build an auditor export pack, verify it offline, tamper, RED
#   2. F2 partial regression baseline green run on the current gate
#   3. F3         canary mint -> observe -> reuse denied
#   4. F6         blast-radius delta report on a policy change
#   5. P1.9a      portal phase 5 push demonstration beat (chained deployment row)
#
# Prerequisites (checked in section 0): venvs in each of the three repos.

set -euo pipefail

OAA="$HOME/Projects/open-agent-assurance"
RED="$HOME/Projects/raucle-agent-red"
RAUCLE="$HOME/Projects/raucle"
CLOUD="$HOME/Projects/raucle-cloud"
HERE="$OAA/demo/w3"
TRANS="$HERE/transcript-$(date +%Y%m%d-%H%M%S).txt"

banner() { printf '\n===== %s =====\n' "$1" | tee -a "$TRANS"; }
run()    { printf '\n$ %s\n' "$*" | tee -a "$TRANS"; "$@" 2>&1 | tee -a "$TRANS"; }

mkdir -p "$HERE/runtime"
: > "$TRANS"

banner "W3 demo run-through started $(date -Iseconds)"

banner "Beat 0: prerequisites"
run test -x "$OAA/.venv/bin/python" && test -x "$RED/.venv/bin/python" \
  && test -x "$RAUCLE/.venv/bin/python" && test -x "$CLOUD/.venv/bin/python" \
  && echo "all four venvs present"

banner "Beat 1 (F7 hero): auditor export pack, offline verification, tamper RED"
rm -rf "$HERE/runtime/pack" "$HERE/runtime/tamper"
run "$OAA/.venv/bin/python" "$OAA/scripts/build_audit_pack.py" \
  --evidence-store "$OAA/services/investigation-ui/demo_data/evidence_store.jsonl" \
  --trust-roots "$OAA/services/investigation-ui/demo_data/trust_roots.jsonl" \
  --from 2026-10-01 --to 2026-12-31 \
  --out "$HERE/runtime/pack"
run "$OAA/.venv/bin/python" "$OAA/tools/verifier/verify_pack.py" "$HERE/runtime/pack/audit-pack.zip"
run "$OAA/.venv/bin/python" "$OAA/tools/verifier/verify_pack.py" "$HERE/runtime/pack/audit-pack"
cp -r "$HERE/runtime/pack/audit-pack" "$HERE/runtime/tamper"
"$OAA/.venv/bin/python" "$HERE/tamper_beat.py" "$HERE/runtime/tamper" 2>&1 | tee -a "$TRANS"
set +e
run "$OAA/.venv/bin/python" "$OAA/tools/verifier/verify_pack.py" "$HERE/runtime/tamper"
echo "   (exit 1 expected: the tampered pack must verify RED with a named failure)" | tee -a "$TRANS"
set -e

banner "Beat 2 (F2 partial): regression baseline run against the current gate"
run "$RED/.venv/bin/python" "$RED/scripts/red_scheduler.py" run --trigger manual
run "$RED/.venv/bin/python" "$HERE/board_summary_beat.py" "$RED/runs/history.jsonl"

banner "Beat 3 (F3): one-time canary, deterministic verdict, reuse denied"
rm -rf "$HERE/runtime/canary"
mkdir -p "$HERE/runtime/canary"
run "$RAUCLE/.venv/bin/python" -m raucle.cli canary mint --run-id w3-demo-run \
  --store "$HERE/runtime/canary/agents.json" \
  --ledger "$HERE/runtime/canary/ledger.jsonl" \
  --receipts "$HERE/runtime/canary/canary-receipts.jsonl" \
  2>&1 | tee "$HERE/runtime/canary/mint.txt" | tee -a "$TRANS"
CANARY_VALUE="$(grep -o 'rak_[0-9a-f]*' "$HERE/runtime/canary/mint.txt" | head -1)"
run "$RAUCLE/.venv/bin/python" -m raucle.cli canary observe --value "$CANARY_VALUE" \
  --store "$HERE/runtime/canary/agents.json" \
  --ledger "$HERE/runtime/canary/ledger.jsonl" \
  --receipts "$HERE/runtime/canary/canary-receipts.jsonl"
set +e
run "$RAUCLE/.venv/bin/python" -m raucle.cli canary observe --value "$CANARY_VALUE" \
  --store "$HERE/runtime/canary/agents.json" \
  --ledger "$HERE/runtime/canary/ledger.jsonl" \
  --receipts "$HERE/runtime/canary/canary-receipts.jsonl"
echo "   (nonzero exit expected on reuse: denied:already-consumed)" | tee -a "$TRANS"
set -e

banner "Beat 4 (F6): blast-radius delta report on a policy change"
run "$RAUCLE/.venv/bin/python" "$HERE/delta_beat.py" "$HERE/runtime"

banner "Beat 5 (P1.9a, demonstration only): portal phase 5 push outcome"
run "$CLOUD/.venv/bin/python" "$HERE/phase5_beat.py" "$HERE/runtime"

banner "Run-through finished $(date -Iseconds)"
echo "transcript: $TRANS"
