# oaa-ep-aec — EP-AEC-v1 authorization evidence chain (EPIC M K1)

Implements the EP-AEC-v1 Action Evidence Chain object and the fixed-limit
requirement evaluator from
`draft-schrock-ep-authorization-evidence-chain-08` (4 Oct 2026), plus the
`EP-AEC-REPLAY-v1` replay record, over raucle gate receipts held in the
verbatim evidence store produced by `oaa-raucle-adapter`.

- `objects.py` — JCS (RFC 8785) canonical serialisation for the used subset,
  Action Object builder from a receipt index row, AEC object assembly, the
  requirement-expression evaluator (AND/OR/NOT/parens over component-type
  atoms) with the draft's fixed limits (4096 bytes, 256 tokens, 32 paren
  levels), and replay-record assembly.
- `generator.py` — builds an AEC envelope from an evidence store directory of
  `{receipt_hash, jws}` JSONL lines. By default the raw JWS is referenced by
  `receipt_hash` only and NEVER embedded (`allow_embed_jws=False`).

raucle is an OPTIONAL dependency; without it the generator still builds AECs
from classification results supplied by the caller. Integration tests that
classify real fixtures via the pinned raucle v0.23.5 worktree (git 63edacd)
skip when raucle is absent. Findings: `docs/spikes/K1-epaec-findings.md`.