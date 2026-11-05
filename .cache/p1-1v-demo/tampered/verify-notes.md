" Offline verification notes

## Prerequisites

You need only Python 3.11+ with the `cryptography` package (`pip install
cryptography`). No network connection is used, wanted, or trusted at any
step, and the pack itself carries the pinned key snapshot it is checked
against: no raucle installation, no gateway, and no operator access are
involved. The verifier ships separately as `tools/verifier/verify_pack.py` in
the source repository; ask the operator to hand it to you alongside this
pack, or write your own — the manifest tells you everything it should check.

## Steps

1. If you received the `.zip`, unpack it once into a directory.
2. Run: `python verify_pack.py <unpacked pack directory>`
3. Read the verdict. Green means every manifest digest matched, every
   receipt signature validated against the embedded key snapshot within
   its validity window, and every claimed timestamp anchor carried its
   token. Red names the exact file or receipt that failed.
4. Exit code 0 is green; 1 is red. A "warning" (claim-sheet guard missing,
   for instance) does not change the exit code but is printed prominently.

## Expected contents

- `receipts.jsonl` — 2 receipt envelope(s), byte-exact.
- `keys/` — the pinned key snapshot (public keys only), embedded so the pack
  verifies against nothing outside itself.
- `signatures/` — the full signature bundle: every envelope a pack claim
  depends on, including chain receipts a resolved graph references beyond
  the query window (see that directory's README when none were needed).
- `timestamps/` — 0 RFC 3161 token(s) (see that directory's README when none).
- `policies/` — not included — the policy set and its deployment-chain receipts were not accessible at pack time; coverage here is unverified.
- `chain_graph.json` — the chain-graph slot (its resolved status is reported by the verifier).
- `claims.md` — the plain-English claim sheet with its mandatory no-claim guard.

If any of the above is missing, the verifier will say so by name. It is
normal for this pack to contain no policy evidence and no timestamp tokens:
those absences are stated in the claim sheet rather than papered over.
