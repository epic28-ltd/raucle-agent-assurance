# UI-02.3 console-v3 findings: quiet-SaaS rebuild

Date: 2026-11-04. Scope: services/console shell rebuild on the Elera-derived
quiet-SaaS reference. Nothing external is fetched at runtime.

## What shipped

- **Design-token layer** (`static/tokens.css`): every palette, hairline,
  accent, radius and type value of the reference as custom properties, with a
  full dark equivalent block under `[data-theme="dark"]` (bg #15161A, cards
  #1D1E23, hairlines #2A2B31, same accents).
- **Shell stylesheet** (`static/app.css`): sidebar (fixed 260px, hairline
  right edge), topbar (transparent, page title block, search pill with `/`
  kbd hint, icon buttons, charcoal CTA, avatar + dropdown), cards (white,
  16px radius, 1px hairline, near-no shadow), tinted pills (not saturated
  chips), 8px-radius charcoal icon tiles. Inter is the shell font, vendored.
- **Tabler removed**: `static/vendor/tabler/` deleted; NOTICE updated (removal
  recorded, Inter licence retained). The shell links only tokens.css +
  app.css. `/static` is now mounted whole so the stylesheets serve.
- **Dark mode**: toggle in the topbar, persisted in localStorage (`rc-theme`);
  same for the sidebar collapse (`rc-collapsed`).
- **Overview maps to the reference grid** (row1 25/43/30, row2 2.4fr/1fr,
  gaps 12-16px):
  - Verification health: single donut gauge (pale track, green arc = valid
    share, big centred valid count) with tinted green / red footer counts.
  - Evidence states: four rounded-cap bars per ADR-0001 state on pale tracks;
    the unknown-key bar carries a thin black tick at the coverage line
    (`/api/config` now exposes `coverage_target_pct: 95`) and flips between
    In coverage / Needs attention pills.
  - Findings: proxied rows (new console endpoint `/api/assurance/findings`)
    with rule_id, explanation, tinted severity pill and grey
    "suppressed with reason" rows carrying the documented reason.
  - Recent activity: hairline-divided rows with charcoal event tiles and
    honest relative times from the server-supplied `ts` ("4m ago" style).
  - Evidence this window: 40px big number over one stacked rounded-cap bar
    (valid / invalid / un-proven / not-applicable) and a dot legend with
    counts on hairline-divided rows.
  - Guidance banner: mint panel with dark-green tile; headline + plain
    explanation picked in priority order invalid > bypass_suspected >
    receipt_missing > unsupported_schema > ambiguous > duplicate > all-clear,
    driven by the live distributions and suppressed finding rules.
- **Guidance model honesty**: sentences are generated only from data in the
  window; no intent attribution, no compliance claims. When the add-in is
  offline the banner says so explicitly rather than dressing demo figures as
  live.

## Known trade-offs

- Findings rows carry no wall-clock timestamps in the fixture set, so the
  findings card labels its window honestly ("this demo window") instead of
  inventing relative times; the activity feed does have server timestamps.
- The guidance banner sits in the bottom row's wide column (row 3) per the
  reference's bottom-left mint panel.
- Sidebar product-count badges: only Notifications carries a real count (from
  `/api/overview`); product rows use status dots, per spec "no inline text
  chips".

## Counts

- Console tests: 23 passed (suite baseline held + 5 new UI-02.3 tests).
- ruff: clean.
- Vendored size removed: tabler.min.css + tabler-vendors.min.css + licence
  (~350KB of third-party CSS) gone; Inter woff2 (one file, ~100KB) kept.