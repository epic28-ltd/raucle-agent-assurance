# Raucle Agent Red — add-in roadmap (preview)

Status: **coming soon** (wave 2 of the suite; not purchasable yet). This is
the roadmap doc the Console's Red preview card links to (BEH-01 console
work). Nothing in this file is a commitment of scope or dates.

## What Red will do

1. **Gate fuzzer.** Replays hostile and edge-case tool calls against the
   operator's live policy: prompt-injection payloads in tool arguments,
   constraint edges (boundary values, forbidden-field combinations), intent
   mismatches, delegated-authority abuse. Every fuzz case runs through the
   real gate and is receipted like any other call.
2. **Tamper attempts.** Deterministic tamper probes against receipts and
   evidence: signature swaps, field edits, chain re-ordering, replay, and
   schema downgrades. Expected result is always fail-closed; anything else
   is a defect.
3. **Findings pairing.** Red reports through the same Assurance findings
   board (rule ids + evidence refs + suppression semantics), so red work
   becomes triaged, evidenced findings rather than a separate report.

## Integration with Assurance

- Red never writes evidence directly: it runs the gate and tamper probes,
  and the evidence plane indexes what happened. Findings land as board rows
  with severity and confidence classes.
- Console surfaces Red as an add-in card (`not_purchased` until purchased);
  the BEH-01 preview card shows the two capability rows above and links
  here.

## Non-goals (repeated from the EPIC plan)

- Red does not proxy the model path; it drives the gate like any other
  caller.
- No outreach, no third-party publication of findings; results stay in the
  operator's own board and evidence store.