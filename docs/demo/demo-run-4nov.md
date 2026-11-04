# Demo run transcript — 4 November 2026 (executed end-to-end)

Companion to `docs/demo/demo-script.md`. UI served live during the run (port 3410).

## Act 1 — canonical evidence (Raucle Agent Trust receipts)

Evidence store = the real obs01 SPIKE run (one allow, one deny), file sha256
`0afe93c937b96c304f8cb57cc61905e5e9178d94a92bb7439b26d372a0f95de7` (matches the spike's
recorded immutability proof):

```
sha256:a3e29df11123ffc4c65fd50a5841d356b191a0fa85ff5b04fe970ed6f74379d5   {"receipt_hash": ..., "jws": "eyJhbG...zFkO"}
sha256:7ad7bb9a68f0c3d50b1d24451b4caa2059ced33d33d0e53755fe94fc18b787db   {"receipt_hash": ..., "jws": "eyJhbG...zg4N"}
```

Minimal envelope only: `{"receipt_hash", "jws"}` — nothing else ever stored.

## Act 2 — correlation with explicit unknown states (UI, run-sim-02)

`GET /api/runs` → two runs; run-sim-02 carries 9 privileged spans with the full state
vocabulary rendered per span. Verified traces on screen:

| trace label | verification | correlation |
|---|---|---|
| ambiguous: 2 receipts on 1 trace | valid / **unknown_key** | **ambiguous** (receipts listed, "needs human review") |
| duplicate: same receipt twice | valid | **duplicate** ("collapsed 2 deliveries; provenance preserved") |
| late_arrival outside window+grace | **unsupported_schema** | **late_arrival** |
| verification pending (async) | **pending** (explicit_unknown) | matched |
| not_applicable (schema v0) | **not_applicable** | matched |
| verifier offline at ingest | **unavailable** (explicit_unknown) | matched |
| matched, verified | valid | matched |
| receipt_missing (suppressed SEC-001) | **unavailable** "absence is a coverage gap, not a result" | **receipt_missing** |

No state is blank; every unknown is a first-class badge.

## Act 3 — offline verification over canonical bytes

`classify()` over the two canonical receipts with the archived gateway key:

```
sha256:a3e29df1... -> valid
sha256:7ad7bb9a... -> valid        (the DENY receipt — gate refusal is evidence, verified too)
verifier_version: raucle 0.23.5 (git 63edacd)
checks: jose_header_parsed (kid='1515bd8cf636bf4b', crit=['raucle/v1'], alg='EdDSA')
        event_time from signed iat: 2026-11-04T08:43:39+00:00
        trust_roots_at_event_time -> ['1515bd8cf636bf4b']
        receipt_hash == sha256(compact jws)
        ProvenanceVerifier.verify_chain(temp, strict=True) -> report.valid == True; errors=[]
```

Demo-caught fix: `evidence_plane.classify` had the str-vs-bytes PEM bug (racle verifier
requires `dict[str, bytes]`); corrected and regression-committed during this run (8d43ebf).

## Act 4 — findings and suppressions

```
SEC-001 | high     | suppressed: True  | reason: documented maintenance-window coverage gap (CHANGELOG 2026-11-04)
SEC-002 | medium   | suppressed: False |
```

Suppression retains the finding with its reason; nothing is silently hidden.

## Act 5 — the honest report (mandatory limits, from example-report.md)

- Scope: gated paths only; ungated paths are out of scope and out of evidence.
- Coverage per tool (custody map): `file_write/http_fetch/shell = gate`, `read_file/write_file = unverified`.
- Tool-side audit events: "not provided — coverage unverified".
- One-line trust model: integrity and authority within trust policy `evd-trust-1`; never safety, appropriateness, or compliance.
- "A receipt or this report does not establish legal or regulatory compliance of any kind."

## Act 6 — operational reality

Runbook with proven backup/restore round-trip (hash-verified), restart recovery (documented 19 s manual), upgrade checklist (dual-mode gate recheck). Load smoke: 1,201 runs / ~24,020 spans, no measurable producer overhead. SIEM webhook: deterministic event ids, dead-letter replay.

## Closing statement

Raucle Agent Trust proves what was allowed to run; Raucle Agent Assurance detects what ran
outside it; Raucle Agent Red (next wave) finds what gets through — receipted attacks, verifiable
pentest evidence. Sovereign by construction: signed locally, verified anywhere.