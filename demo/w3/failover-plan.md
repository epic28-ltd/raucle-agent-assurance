# W3 hero demo: rehearsal failover plan (P1.D3r)

Status: honest planning document, written after a full rehearsal of all
five beats. It contains no guarantees about anything that is not checked
here. Every fallback below is "reduce to the shipped artefact", never
"invent an output".

General principles:

- A failed beat is shown as failed. Never fake a pass, never edit the
  runtime to make a beat go green before the audience.
- Fallback artefacts that are recorded transcripts are labelled as
  recorded, on screen, in one sentence.
- Switch to fallback only when the time-box below expires, not on the
  first wobble.

## Environment-level failures (before any beat)

### The offline laptop misbehaves (venv broken, python crashes, disk panic, accidental network exposure)

1. Check first: `test -x` on all four venvs (beat 0 of runbook.sh);
   `python -c "import sys; print(sys.version)"` in each venv; the last
   20 lines of the transcript for the actual error.
2. Fallback: none at demo time for a broken checkout on the laptop
   itself. The laptop is the demo. If the laptop is dead: any second
   machine that has the three repos plus venvs can run runbook.sh from
   scratch; nothing in the demo requires this specific machine except
   the recorded transcript, which is one file, copyable.
3. Honest note: the demo has no cloud path. If loopback networking is
   unavailable, beats 1, 4 and 5 still run (file only), beat 2 depends
   on the red scheduler's local mode, and beat 5 binds loopback only.
   Do not promise the whole run works networkless in the room without
   having rehearsed it networkless.
4. Time-box: 3 minutes on beat 0. If venvs are not healthy by then,
   present the recorded transcript instead.

### The demo VM (or laptop) is slow

1. Check first: which beat is slow. The known slow beat is beat 2 (the
   full regression run, hundreds of tests). If a beat hangs rather than
   being slow, look for a subprocess wedged on a lock file.
2. Fallback: run beats individually rather than via runbook.sh, and cut
   beat 2's per-test verbosity by using the recorded
   transcript-20261105-010748.txt for beat 2 plus a fresh
   board_summary_beat.py over run history (the summary board renders in
   seconds even when the full run does not).
3. Time-box: 4 minutes for beat 2 wall time; 2 minutes for any other
   single beat. At expiry, switch that beat to its recorded transcript
   fallback and say it is recorded.

## Beat 1, F7 hero: pack build, offline verify GREEN on clean, tamper RED

Typical failures: build_audit_pack.py empty pack (bad --from/--to
window), verifier unexpected FAIL, tamper beat does not produce RED.

1. Check first: the pack directory exists and audit-pack.zip plus the
   directory form are both present; the verifier's named failure lines,
   verbatim (they say what is wrong, so read them before acting).
2. Fallbacks, in order:
   - if the live build fails, ship a pack built beforehand in the same
     window and verify that (build time is not part of the demo claim;
     verification is);
   - if the live tamper does not turn RED, re-run the verifier on the
     runtime/tamper copy once; if it is still green, say so honestly
     and replay the recorded tamper RED section of
     transcript-20261105-010748.txt, labelled as recorded;
   - never tamper the pristine pack copy, only the runtime/tamper copy.
3. Time-box: 90 seconds per verifier invocation after the pack exists;
   5 minutes total for the beat.

## Beat 2, F2 partial: regression baseline green board

Typical failures: red_scheduler run throws mid-run, drift rows appear,
the board renderer chokes on the history file format.

1. Check first: `runs/history.jsonl` gained a new line; the scheduler's
   own traceback is the diagnosis, do not paraphrase it.
2. Fallbacks, in order:
   - rerun once with the same arguments (transient scheduler flakes did
     occur during development and single rerun has fixed them);
   - if the run cannot complete in room, render
     board_summary_beat.py over the pre-existing history (it shows
     exactly the state before the demo) and say so;
   - ultimate fallback: the recorded beat 2 transcript section, labelled
     recorded.
3. Time-box: 4 minutes for the scheduler run, then one rerun of the
   same length maximum, then fall back to the summary board over
   existing history.

## Beat 3, F3: one-time canary, observe, reuse denied

Typical failures: the mint value regex misses (CLI format changed),
observe says denied immediately (stale ledger), reuse is not denied.

1. Check first: runtime/canary/ is fresh (the runbook wipes it); the
   mint CLI output contains rak_...; the ledger has exactly one entry
   after mint.
2. Fallbacks, in order:
   - if mint fails format-wise, read the value out of the store file
     hash field is not possible (it is stored hashed), so re-mint once
     with a fresh store, ledger and receipts path in a new directory;
   - if reuse is NOT denied, that is a real finding, not a demo
     hiccup: show the actual exit and output, that is more
     interesting than the planned beat; do not paper over it;
   - recorded fallback: the recorded canary section of
     transcript-20261105-010748.txt, labelled recorded.
3. Time-box: 2 minutes, then the recorded fallback.

## Beat 4, F6: blast-radius delta report

Typical failures: the recorded batch fails to import (provenance chain
version drift), the report's receipts section empty, z3-related gap
lines misread as the whole section failing.

1. Check first: delta_report.json written to runtime/; the
   receipt_ids arrays populated; the register sentence present.
2. Fallbacks, in order:
   - rerun delta_beat.py with a clean runtime/ delta working area;
   - print the last committed delta-report.json from a prior rehearsal
     and say it is from the prior rehearsal (this artefact is
     deterministic over its recorded batch, so identical input gives
     identical output, and that is testable, but only claim it if
     re-checked);
   - the recorded beat section of
     transcript-20261105-010748.txt, labelled recorded.
3. Honest framing to keep in mind for questions: the invariant diff is
   heuristic without z3 installed; delegation-hop impact is not
   evaluated without chain graphs. Those gap lines are in the report
   on purpose. Do not over-claim.
4. Time-box: 3 minutes.

## Beat 5, P1.9a (demonstration only): portal phase 5 push outcome

Typical failures: import errors from raucle/raucle-cloud version
drift; the portal app fails to start on a busy loopback port; the
temp server thread does not stop.

1. Check first: the traceback module and line, verbatim. The
   rehearsal hit exactly one of these, already fixed in this repo: the
   raucle wheel pinned in the raucle-cloud venv predates
   raucle.chain_graph, so phase5_beat.py now puts the checked-out
   raucle repo first on sys.path (see
   tests/audit-pack/test_w3_phase5_beat_paths.py, which pins that
   resolution). If raucle-cloud moves to a new module layout again,
   the beat will traceback the same way: read the line before
   improvising.
2. Fallbacks, in order:
   - rerun the beat once (the temp server and temp config are created
     per run, so reruns are clean);
   - run raucle-cloud's own test module
     (tests/test_phase5_push.py::test_full_vertical equivalent) and
     present its green output;
   - present the recorded deployment row (push_status accepted,
     chained true, sha256 receipt hash prefix) from
     transcript-20261105-010748.txt, labelled recorded.
3. Time-box: 2 minutes, then rerun once, then recorded fallback.

## End-to-end fallback ladder

If anything above is too tangled to untangle live:

1. Present the recorded transcript of the 5 November 2026 clean run
   through (transcript-20261105-010748.txt) section by section, always
   labelled as the recorded run.
2. Present the current repo state (git log for the demo commits) to
   show what shipped since.
3. Say the honest sentence: the live run failed, here is the reason,
   here is the recorded evidence that this beat worked when the
   environment was healthy, and the fix is committed and covered by a
   test.

Nothing above invents a pass. Everything above either re-uses a
shipped artefact or a labelled recording.
