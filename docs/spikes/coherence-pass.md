# UI-05 coherence pass: one shared counting module, both surfaces

The QA review found the CRITICAL blocker for a verification product: count
incoherence. KPI numbers disagreed with their own chips (3 vs 4, 9 vs 5,
4 vs 1), scope chips disagreed with column badges, the board carried two
counting taxonomies, the console's pinned figures disagreed with the
add-in's live counts, and 'Open: N' was unlocatable. Every number on both
surfaces now comes from ONE module.

## Shared module

`services/investigation-ui/src/oaa_investigation_ui/counting.py` exposes
`count_evidence(data_dir, at)` — one function over the same demo data
source — and the app exposes it on **GET /api/counts** (full breakdown):
verification buckets, correlation states, health traffic lights,
triage/findings buckets, runs, receipts row facts. The console imports the
same module for `/api/overview` (trust figures + offline fallbacks) and
proxies `/api/assurance/counts`. Nothing computes its own numbers any more;
the old pinned 9/10/5 console constants are gone.

## Bucket taxonomies (single source)

- Verification (privileged-span index plane, 16 rows; ADR-0001 states folded):
    valid 8 · unproven 2 (unknown_key 1 + pending 1)
    unaccounted 1 (unsupported_schema 1; invalid folds here) · exempt 5
    (unavailable 4 + not_applicable 1). Sum 16 = distribution sum.
- Correlation (ADR-0002): matched 6 · matched_degraded 1 · ambiguous 3
  · duplicate 1 · late_arrival 1 · receipt_missing 2 · trace_missing 1
  · pending 1. Sum 16.
- Findings triage (14 findings): open 10, split needs_investigation 4
  · unproven 5 · coverage_gaps 1; closed 0; suppressed 4.
  open + closed + suppressed = total. The three lens chips partition open.
- Traffic lights (span plane): healthy 4 · at_risk 9 · needs 3
  (healthy + at_risk + needs = 16).
- Receipts (row plane, honest labels): 14 receipts minted (2 canonical
  store envelopes + 12 synthetic index rows), 14 verification rows, 9 valid.

## Board mapping (documented in UI-02.4-findings-board.md)

- KPI strip = counting chips = member counts of the same buckets:
  Needs investigation 4 · Unproven 5 · Coverage gaps 1 ·
  Evidence verified 8 (index-plane metric, real count in the chip).
- Columns are lifecycle states: Needs investigation (New) /
  Investigating / Suppressed / Closed (green-tinted, was 'Resolved').
  'Coverage gaps' is deliberately NOT a column: it is a chip + KPI metric.
- Board outcome card: Closed + Suppressed + Open = total (computed over
  the shown set, so it stays coherent under filters), and Open equals the
  items visible across the open columns.

## QA copy/consistency fixes (this pass)

- Time pills neutral grey; amber reserved for un-proven only (stale stays red).
- Solid dark charcoal only on ACTIVE chips; ID tiles/KPI tiles use a muted
  dark token (--el-tile) so tiles and active chips are visually distinct.
- 'live' chip replaced by a real count pill with an index-plane label.
- Pluralisation fixed via a shared helper ('1 coverage finding').
- Find placeholder 'Find (rule, reason, run, ref)…' confirmed; guidance
  link no longer wraps mid-link.
- Card descriptions clamped to 3 lines with a 'More' affordance that opens
  the full guidance drilldown inside the card.
- Empty columns show 'No findings here' microcopy (columns keep min-height).
- 'index-plane only · evidence never re-rendered raw' moved out of the
  header into a tooltip on an 'index-plane' badge.

## Tests

`services/investigation-ui/tests/test_counting.py` pins the arithmetic
(7 unit tests + 1 cross-surface test); board/service tests rewire chips,
KPIs and selectors to the shared counts; the console tests assert its
overview trust figures equal `count_evidence` output. Suite green, ruff
clean.