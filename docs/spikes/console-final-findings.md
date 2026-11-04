# Console final fix pass (UI-02.5)

QA final blockers from the vision review of `static/preview/console.png`, and
what was changed. Nothing redesigned; static shell only
(`static/index.html`, `static/app.css`, `static/tokens.css`).

## Fixed

1. **Guidance banner colour semantics** - `pickGuidance` now returns a
   severity bucket (`act` / `look` / `good`) and `guidanceBanner` sets
   `banner banner-<tone>`. Red tint (`--act-bg` / `--act-ink`, red icon tile)
   for invalid, bypass suspected (SEC-009) and receipt missing (SEC-001);
   amber for unsupported schema, ambiguous and duplicate correlation, and
   for the add-in-offline case; mint green only for the all-clear line.
   The observed green-on-SEC-001 mismatch is gone (both themes shot with a
   SEC-009 bypass finding live: banner renders red).
2. **Severity pills** - `SEV_TONE` maps high/critical to the red pill,
   medium/moderate to amber, low/info to grey. No more uniform grey badges.
3. **Suppressed chip** - `suppressed with reason` is now a grey outline chip
   (`border-radius:999px`, hairline border) in a right-hand rail under the
   severity pill; the reason line below is a full-width label/value row.
4. **Footer anchoring** - every card is a flex column with `.card-body`
   flex-grow and `.card-ft` at `margin-top:auto`, so the bottom edge of each
   row is closed and the 'What is this?' links share one baseline.
5. **Bucket taxonomy** - the gauge foot now computes from the same
   verification distribution as the Evidence states card: green `+N valid`,
   amber un-proven (unknown key plus pending), red unaccounted
   (unsupported schema / invalid), grey exempt (unavailable plus not
   applicable). The old `-N unknown / invalid` line is gone. Pending and
   Not applicable bars were added to Evidence states so its rows sum to the
   row total; the Evidence verified stacked bar and dot legend use the same
   taxonomy and counts (bar widths are count/total), with the exempt grey
   segment visible and named in the card footer.
6. **Coverage tick** - the allowance tick sits at `left: calc(95% - 1px)`,
   is 14px tall and uses the dark ink token (reversed to near-white in dark
   mode).
7. **Truncation** - card titles and qualifiers render single-line with
   ellipsis plus a `title` attribute (full text on hover); SEC rule ids and
   subjects are `white-space:nowrap` with no hyphen breaks; the Evidence
   card was shortened to 'Evidence verified' so the title stays single line;
   caption and legend counts align right.
8. **Gutters** - topbar, page head and content all use the same symmetric
   24px padding; the avatar sits clear of the viewport edge.
9. **Copy** - alpha line is now user-facing without italics or developer
   jargon: 'Alpha preview: figures reflect this session. Demo fixtures are
   used where an add-in is offline.' Bottom guidance banner spans the full
   grid width (`grid-template-columns:1fr`) so the bottom edge closes.
10. **Screenshots** - both themes re-captured full-page into
    `static/preview/console.png` and `console-dark.png` (via scratch port
    3414; `RAUCLE_CONSOLE_URL` env switch added to
    `tests/screenshot_console.py`, production remains 3412).
11. **Tests** - all green (26 passed, up from 24; two new: severity pill
    tint mapping, banner tint class switching). Ruff clean.

## Verified

- Light and dark full-page shots inspected: banner red-tinted (live
  bypass-suspected state), spans full width, unclipped; gauge foot figures
  wrap cleanly in the narrow column; evidence state rows, stacked bar and
  legend all reconcile at 16 rows.