# W3 hero demo (Sprint 1 P1.D3 + P1.9a)

Home for the W3 demo artefacts: this directory. One clean run-through was
executed end to end on 5 November 2026; the recorded transcript of that
run is trans-20261105-010748.txt (runtime outputs land in runtime/, which
is gitignored).

Framing line, say it in the session:

> reconstructability, not log completeness

## Runbook

`runbook.sh` runs all five beats. Each beat is a separate script in this
directory; nothing leaves the machine and all services bind loopback.

## Recorded clean run (5 November 2026)

### Beat 1, F7 hero: auditor export pack, offline verification, tamper RED

- `build_audit_pack.py` over the demo evidence store: 2 receipts, 1 key,
  8 manifest files, zip + directory.
- `tools/verifier/verify_pack.py` over the pack: all checks PASS (8/8),
  `OVERALL VERDICT: GREEN`.
- Deliberate tamper on a copy (4 trailing JWS bytes flipped on receipt 1,
  original untouched): verifier answers RED with two named failures:
  - `[FAIL] manifest-integrity`: receipts.jsonl recorded sha256 differs
    from the file on disk (tampered after export);
  - `[FAIL] receipt-signatures`: receipt 1: receipt_hash does not
    re-derive from the receipt bytes (tampered).
- Exit 1 on the tampered pack, exit 0 on the clean pack.

### Beat 2, F2 partial: regression baseline green run on the current gate

- `red_scheduler.py run --trigger manual` (raucle-agent-red):
  337 pass, 0 violation, 0 drift; regression reopened=0 resolved=0.
- Green board on violations and drift. Honest residual, stated on the
  board and worth a sentence if asked: 3 RED-002 unverified probes
  (tamper suite produced no RED-002 finding in this run mode) and 1
  unexpected row (recipe not yet baselined).

### Beat 3, F3: one-time canary, determinism, reuse denied

- `canary mint` (raucle): mint id shown once, value shown once, stored
  hashed.
- first `canary observe` of the exact value: status `observed`, receipt
  written to the canary receipt stream.
- second observe of the same value: status `denied`, reason
  `denied:already-consumed`, exit 1.
- The verdict is deterministic for a given canary and its ledger state.

### Beat 4, F6: blast-radius delta report on a policy change

- `delta_beat.py` runs a recorded batch (provenance chain + replay
  harness) and prints the accountable delta report:
  flipped decisions ALERT-to-BLOCK, every flip traced to its receipt ID;
  authority paths with rule IDs; invariant diff with an honest gaps
  section (`z3 not installed: invariant section is heuristic, not a
  proof`; delegation-hop impact not evaluated without chain graphs).
- The report closes with a register sentence every number of which is
  traceable to a receipt ID.

### Beat 5, P1.9a (demonstration only): portal phase 5 push outcome

- `phase5_beat.py` (raucle-cloud) drives the shipped phase 5 path end to
  end (registry -> signed push -> gate) and prints the deployment row.
  Recorded outputs: `push_status: accepted`, chained true, remote
  receipt hash `sha256:65e4203ef5a6912db4fd859508085dc2b...`.
- Demonstration beat: it exercises shipped machinery and adds nothing.

## Pre-existing failures: two test_code_authorship tests (raucle): documented, not fixed

`tests/test_code_authorship.py::test_hook_script_end_to_end` and
`::test_hook_survives_missing_transcript` both fail in the raucle suite
(6 pass). Both failures share one root cause, confirmed by hand:

`shutil.which("raucle")` inside `integrations/hooks/raucle_session_stop.py`
resolves to a `raucle` wrapper that is first on PATH from the local Python
3.14 toolchain environment (~/.hermes/tools/python-3.14.9...), and that
environment has no `cryptography` package. The hook therefore signs via a
sign subprocess that exits with "No module named 'cryptography'", and the
hook deliberately degrades silently (exit 0, stderr note, no receipt), so
both tests fail on receipt presence/validity:

- test_hook_script_end_to_end: `assert out.exists()` fails;
- test_hook_survives_missing_transcript: `assert result["valid"]` fails.

Running the same sign command directly with the raucle venv interpreter
succeeds (`VALID code_authorship receipt: ...`), so the code path is
sound; the failure is environment-shaped (a `raucle` shim on PATH that
cannot import `cryptography`). Candidate fixes, not applied here: prefer
the invoking interpreter (sys.executable -m raucle) before
shutil.which("raucle"), and/or surface the sign failure louder than a
one-line stderr note. Both tests were left failing; this note is the
P1.9a requirement.

## Notes

- The F7 pack build/verify beat and the canary ledger keys are session
  demo artefacts; the pack lives only in runtime/ (gitignored). No
  secrets are committed.
- Everything in the run is loopback or local-file only.
