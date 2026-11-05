# Receipt-claim sheet (AUD-01 auditor export pack)

Generated: 2026-11-05T12:00:00+00:00
Query window: 2026-11-04T08:43:39+00:00 .. 2026-11-04T08:43:39+00:00 (event time, signed iat)

## What this pack contains

- **2** receipt envelope(s), copied byte-exactly into `receipts.jsonl`.
- A trust-root snapshot of **1** public signing key(s) (public halves
  only — no private key material exists in this pack) under `keys/`.
- **0** RFC 3161 timestamp token(s) extracted into `timestamps/`.
- Policy evidence: not included — the policy set and its deployment-chain receipts were not accessible at pack time; coverage here is unverified
- Chain-graph slot: `chain_graph.json` is recorded as pending P1.1a wire-up.
- Signature bundle: complete within the query window: every receipt the resolved chain graphs reference is carried in `receipts.jsonl` (the pack is self-contained: every
  envelope a claim here depends on is shipped inside it).
- A pinned key snapshot with the public half of every signing key used
  inside the window, so re-verification needs nothing else (no network,
  no raucle installation, no operator access).
- This file (`claims.md`), a `manifest.json` of per-file sha256 digests, and
  `verify-notes.md` telling you how to check all of it, offline.

## What you can check with this pack

- That every packed file matches its recorded sha256 digest (the manifest) —
  this detects post-export tampering.
- That each receipt's receipt_hash re-derives from its JWS bytes.
- That each receipt's Ed25519 signature validates against the embedded key
  snapshot, within that key's stated validity window (trust policy
  `evd-trust-1`: integrity and authority only — nothing further).
- That receipts which claim an RFC 3161 anchor carry the matching token.

## What this pack does NOT contain

- Any private key. Verification is genuinely offline.
- Evidence from outside the query window (unsampled sinks, prior retention
  windows, ungated paths). Absence here is not absence everywhere — the
  boundary above is the whole scope.

## Mandatory no-claim guard

This pack records what was cryptographically observed inside a deliberately narrow scope. It does not establish legal or regulatory compliance, and it asserts no certification, no approval, no accreditation, no attestation, and no warranty of any kind.

No statement in this pack, and no receipt in it, may be read as advice
about safety, appropriateness, or any regulated outcome.
