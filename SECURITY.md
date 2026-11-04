# Security Policy

Open Agent Assurance is a companion layer around a policy-enforcement gate
that mints signed, independently verifiable evidence. Its security posture
inherits the project's design invariants (README; docs/adr/0001):

- **Never mutate canonical evidence.** The gate's `{receipt_hash, jws}` JSONL
  bytes are stored verbatim; derived state lives in a separate index only.
- **`valid` is never inferred from missing data.** Unknown, not-applicable,
  pending and unavailable states stay schema-distinguishable.
- **The companion is never the enforcement authority.** Its failure or absence
  must not change the gate's decisions.
- **Versioned trust roots.** Retired signing keys are archived, never deleted;
  verification selects roots by key_id and event time.

## Reporting a vulnerability

Do NOT open a public GitHub issue for security problems.

Contact: craigamcw (local project, pre-publication — use private contact
channels). Please include: affected component, reproduction steps, and any
evidence artefacts that demonstrate the issue (synthetic data only — never
send real production evidence).

## Secrets handling

- Signing keys (`.pem`), `.env` files and credentials are git-ignored and must
  never be committed.
- The local Langfuse deployment keeps secrets in a local env file; see
  deploy/compose/README.md.
