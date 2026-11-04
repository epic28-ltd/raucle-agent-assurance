#!/usr/bin/env bash
# Local pre-publish gate for Raucle Agent Assurance
# Mirrors what SonarCloud would catch, minus the cloud: lint/format, SAST,
# dependency CVEs and secret detection. Run before every push.
# Usage: ./scripts/local-gate.sh          (fail on any finding)
#        ./scripts/local-gate.sh --warn   (report only)
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
MODE="${1:-strict}"
VENV="$ROOT/.venv/bin"
FAIL=0

step() { printf '\n== %s ==\n' "$1"; }

step "ruff format --check"
"$VENV/ruff" format --check . || { FAIL=1; $VENV/ruff format --check . 2>&1 | tail -5; }

step "ruff check"
"$VENV/ruff" check . || FAIL=1

step "bandit (SAST on production code; tests excluded - fixture/assert noise documented)"
"$VENV/bandit" -r packages services integrations \
  -c "$ROOT/scripts/bandit.yaml" -q -f custom --msg-template "{abspath}:{line}: {test_id}: {msg}" \
  || FAIL=1

step "semgrep (security + secrets)"
"$VENV/semgrep" scan --config p/default --config p/secrets --metrics=off \
  --quiet --error-on-warning --text 2>/dev/null || FAIL=1

step "pip-audit (dependency CVEs)"
"$VENV/python" -m pip_audit -l --progress-spin off --desc off || FAIL=1

step "tests"
"$VENV/python" -m pytest --tb=line -q || FAIL=1

step "summary"
if [ "$FAIL" -ne 0 ]; then
  echo "GATE: findings above"
  if [ "$MODE" = "strict" ]; then exit 1; else echo "(--warn mode: not blocking)"; exit 0; fi
else
  echo "GATE: clean"
fi