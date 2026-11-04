# The auditor export pack (AUD-01)

*Status: P1.7a/P1.7b, extended by P1.1c (self-contained offline export).
The pack is a directory plus a `.zip`. It is produced by
`ops/audit-pack/pack.py` (operator CLI: `scripts/build_audit_pack.py`) and
checked offline by the standalone verifier `tools/verifier/verify_pack.py`.*

## What the pack is

Someone says: *"prove it to my auditor."* The pack is the machine-readable
answer. It takes a bounded query window — a date range, or one specific
receipt — over the read-only evidence store and assembles everything a
reviewer needs to check the receipts themselves, with no network, no
private keys, and no help from the operator.

| file | contents |
| --- | --- |
| `receipts.jsonl` | the receipt envelopes, byte-exactly as stored |
| `keys/` | the pinned key snapshot (public halves only), embedded so the pack verifies against nothing outside itself |
| `signatures/` | the full signature bundle: chain receipts a resolved graph depends on that sit outside the query window |
| `timestamps/` | RFC 3161 anchor tokens for receipts that claim them; an honest absence note when none do |
| `policies/` | policy files and their deployment-chain receipts when accessible; an explicit absence note otherwise |
| `chain_graph.json` | the chain-graph slot: `pending P1.1a wire-up` without the RAUCLE_OSS_HOME opt-in, or resolved graphs whose node signatures were verified against the pinned snapshot |
| `claims.md` | the plain-English claim sheet with its mandatory no-claim guard |
| `manifest.json` | sha256 of every file above |
| `verify-notes.md` | how to check all of it, offline |

The manifest is **additive**: filling the chain-graph slot in place, or
adding timestamp tokens or policy evidence that did not exist at pack time,
does not change the contract. Other files don't shift.

The query window is bounded by each receipt's signed `iat` — the event-time
rule, not export time. `--receipt-hash` selects exactly one receipt and
overrides the window.

## What an auditor does with it

1. If a `.zip` arrived, unpack it into a directory.
2. Get the verifier script (it ships separately in the source repository;
   it is a single file needing only Python 3.11+ and `cryptography`). No
   network connection is used, wanted, or trusted at any step.
3. `python verify_pack.py <unpacked-directory>`
4. Read the verdict: **GREEN** — every manifest digest matched and every
   receipt verified against the embedded key snapshot within its validity
   window. **AMBER** — cryptography all passed but a warning was raised
   (for example, the claim sheet's guard was removed; ask the operator to
   explain each warning). **RED** — the verifier names the file or receipt
   that failed. Exit code 0 is green, 1 is red.

## What is verified — and what is not

Verification asserts **integrity and authority within trust policy
`evd-trust-1`**: bytes match the key trusted at event time; no more. A
green verdict does not establish legal or regulatory compliance,
certification, approval, accreditation, attestation, or warranty of any
kind — the claim sheet says so on its face, and the verifier treats a claim
sheet without that guard as a warning, not evidence.

Absences are statements too, and they are stated, not papered over:

- No timestamp tokens means no receipt in the window claims an RFC 3161
  anchor. It does not mean timestamps are broken.
- No policy evidence means the pack cannot show policy coverage. Obtain
  the current policy set from the operator separately.
- `chain_graph.json` pending means individual receipts verify fully, but
  the pack does not yet assert how receipt chains connect (P1.1a).
- Anything outside the query window — unsampled sinks, prior retention
  windows, ungated paths — is out of scope and out of evidence. Absence
  here is not absence everywhere.

That boundary is the whole scope; nothing in the pack reaches past it.

## P1.1c: the export is self-contained, and that is proven

Since P1.1c the export is self-contained in a checked sense:

- The build refuses to run when an in-window receipt is signed by a key the
  pinned snapshot does not carry: a pack that could not verify offline is
  never shipped. The refused build names the uncovered key.
- The manifest carries a `pinned_key_snapshot` block (file digest from the
  pack itself plus the pinned key ids) and a `self_contained` block
  (`network: none`, `raucle: not required at verification time`); the
  verifier re-checks the declared digest against the embedded bytes.
- When chain graphs are resolved (the `RAUCLE_OSS_HOME` opt-in), the
  resolver is fed the pinned snapshot itself, so embedded node signature
  states are real verify results, and every receipt the graphs depend on
  beyond the query window ships inside `signatures/`. The verifier fails a
  resolved pack whose graphs depend on receipts that are not shipped.
- The verifier's offline path is proven at runtime, not just asserted: an
  import-boundary test (AST scan) confines it to stdlib plus
  `cryptography`, and a runtime test monkeypatches `socket.socket`,
  `socket.create_connection`, `getaddrinfo`, `http.client` and
  `urllib.request` and asserts verification of both the unpacked pack and
  the zip completes green with zero connection attempts.

Known honest gap: RFC 3161 anchoring is at present local-equivalent only.
Tokens embedded in receipts are exported and matched byte-for-byte, but
the pack performs no external timestamping call when building, and does
not claim TSA-backed anchoring. Tokens extracted from the evidence store
are checked for presence and identity, not TSA-chain validation; a
receipt that claims an anchor carries its token, and that is the whole of
the assertion.
