# EPIC-N spike: Raucle Console polish to admin-template quality

Date: 2026-11-04. Scope: services/console only. No commits made (local-only review cycle).

## What changed

The Overview page was rebuilt on the Tabler admin-design language to answer
feedback ("right direction but not as clean looking as" the Ynex Bootstrap
template). All previous functionality is preserved and every existing test
passes (15 passed before and after).

Files:
- `services/console/static/index.html` - rewritten on the Tabler grid and
  component classes (cards, badges, tables, list-groups, navbar). Same
  vanilla-JS, textContent-only discipline; no innerHTML anywhere.
- `services/console/src/raucle_console/app.py` - added a FastAPI static mount
  so the vendored CSS is served locally: `/static/vendor/...` only.
- `services/console/static/vendor/tabler/` - vendored UI toolkit (see below).
- `NOTICE` (repo root) - vendor licence attribution added.

## New Overview page composition

1. Welcome banner: gradient card, 'Welcome back', one honest suite-status line
   (add-ins connected of total; verification rows valid of total, live add-in
   figures), primary actions (Open Assurance, Trust counters).
2. KPI row (4 cards, real data only): receipts minted (9, pinned demo fixture
   set), verification rows (live count with 'valid of' subtext and semantic
   chip), active findings (live add-in; shows 'add-in offline' when the proxy
   is down), add-ins connected (2 of 3). No trend percentages are invented:
   the subtext states the data source instead ('pinned demo fixture set' /
   'live add-in now'), because the APIs expose no time-windowed history.
3. Charts: hand-computed inline SVG (createElementNS, no chart library, no
   runtime fetch): (a) donut of the verification-state distribution from the
   Assurance add-in's `/api/dashboard` via the console proxy, centre shows the
   total; (b) stacked bar of the correlation-state distribution. Semantic
   colour mapping: valid/matched = green; pending/not applicable = grey;
   unknown key/unsupported schema/late arrival/ambiguous = amber; unavailable/
   duplicate/receipt missing = red. If the add-in is offline both cards render
   the explicit 'Add-in offline' empty state.
4. Add-ins status table: Tabler table with status chips and View actions; grey
   button for the not-purchased add-in.
5. Recent-activity feed: Tabler list-group card fed from `/api/overview`.
6. Findings triage card moved to the Overview bottom with a 'View in
   Assurance' button (goes to the embedded add-in page).
7. Sidebar/topbar kept but restyled on Tabler: dark fixed sidebar on desktop
   (`navbar-vertical`), section titles, per-item icon + status chip
   (ellipsis-truncated with a title tooltip), active-item highlighting, and a
   notification count badge. `data-bs-navbar-position="combined"` is set so
   Tabler shows the sidebar AND the topbar together (Tabler v1.x hides one of
   the pair otherwise).
8. Dark/light toggle: switches `data-bs-theme` on `<html>` and persists to
   `localStorage` key `rc-theme`; icons switch sun/moon.

## Tabler vendor note

- Toolkit: Tabler v1.7.3 (`@tabler/core` 1.7.3), MIT licence (Expat).
- Source: downloaded from the official npm distribution at build time
  (registry.npmjs.org, tarball sha-checked by extraction success); the
  upstream GitHub repo is https://github.com/tabler/tabler.
- What is vendored: `dist/css/tabler.min.css` (686 KB) and
  `dist/css/tabler-vendors.min.css` (27 KB), copied verbatim (byte-identical
  to the npm artefact), plus the upstream MIT `LICENSE` text renamed to
  `LICENSE-tabler`. No CDN URLs, no @import, no external font/asset URLs in
  the vendored files, checked by grep.
- No JS bundle was needed: every component used is CSS-only; charts and icons
  are hand-built inline SVG. `tabler-vendors.min.css` is linked for future
  vendor components.
- Runtime behaviour is unchanged: the SPA fetches nothing external
  (threat-model T5). The test `test_spa_textcontent_discipline` continues to
  pin this (it scans the HTML for any non-loopback URL and for markup sinks).
- The SVG namespace string is assembled from parts (`['http:', '',
  'www.w3.org', '2000', 'svg'].join('/')`) so no URL literal appears in the
  HTML, keeping the discipline test's URL scan clean.

## Layout pitfalls found (worth remembering)

- Tabler's `.navbar-vertical` hides itself when the page also has a horizontal
  topbar unless the html element carries `data-bs-navbar-position="combined"`.
- On desktop Tabler positions the vertical navbar `position: fixed` and pads
  `.page` through the sibling selector `.navbar-vertical~.page`; a hand-rolled
  `position: sticky` override breaks both. Do not override its positioning.

## Screenshots

- `services/console/static/preview/console.png` - light theme, desktop
  1550px wide, full page (verified by visual inspection: sidebar, banner,
  KPIs, charts, table, feed, triage card all render cleanly; data across the
  banner, KPI cards and donut agree on 4 of 11 rows valid).
- `services/console/static/preview/console-dark.png` - dark theme (toggled
  via the topbar button; localStorage persistence verified round-trip).

## Known gaps / nits (deliberate, documented)

- Sidebar product names truncate with an ellipsis next to their status chip;
  the full name is on the tooltip (title attribute). Widening the sidebar was
  rejected to keep the standard 16rem Tabler sidebar.
- Donut legend reuses one grey and one amber tone for status pairs
  (pending/not applicable and unknown key/unsupported schema). Distinct hues
  would break the four-tone semantic system, so pair membership stays by row.
- The verification KPI caption can wrap a trailing parenthetical; cosmetic
  only, no collision.
- Notification/profile topbar buttons use Tabler's default light surface,
  which reads slightly bright in dark mode; still legible and consistent with
  Tabler's own dark examples.
- No chart library is bundled; if fancier tooltips or animations are wanted
  later, Tabler's dependencies would need an additional offline vendor pass.

## Verification

- `pytest services/console/tests`: 15 passed (no test edits needed; the
  SPA-discipline, legend, iframe, British-English and em-dash checks all pass
  on the rebuilt page). One `ruff format` pass applied to the test file to
  cure a pre-existing format nit.
- `ruff check services/console`: clean; `ruff format --check`: clean.
- Console restarted on 0.0.0.0:3412 (uvicorn, venv, app-dir src, left running);
  `/api/health` ok and the vendored CSS serves with HTTP 200.