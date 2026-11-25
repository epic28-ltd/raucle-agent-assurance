# Cryptographic boundaries and signing-key custody

**Status:** Engineering control specification; production implementation and independent review pending  
**Last updated:** 2026-11-25  
**Related:** ADR-0001, threat-model-v1, SECURITY.md, OPS-01 runbook

## 1. Cryptographic claims and boundaries

The repository contains evidence and verification code for signed receipts and
assurance packs. It does not contain sufficient evidence to attest to the
production custody of the upstream Raucle gate's signing private key.

| Mechanism | What the code/evidence supports | What it does not establish |
|---|---|---|
| Ed25519 JWS receipt signature | Signature verification under a supplied public key; receipt hash recomputation; tampering is detectable | That a public key was legitimately issued to a named production organisation unless the trust-root distribution and identity binding are authenticated |
| JCS/canonical JSON | Canonical representation checks described in ADR-0001 | Business correctness, authorisation outside the signed policy context, or non-repudiation of the human/operator |
| `receipt_hash` SHA-256 | Detects byte changes when the expected digest is independently protected | Authenticity by itself; an attacker able to replace both bytes and digest can recompute it |
| Trust-root snapshot | Offline verification can use a preserved public-key snapshot and key ID | Trustworthiness of a snapshot that was not obtained through an authenticated channel |
| RFC 3161 timestamp reference | Can provide an independent time-stamping assertion where present and validated | That every receipt is timestamped, or that the TSA validates business intent |
| Optional ML-DSA-65 packet signature | Test suite covers digest binding, signature verification and malformed/tampered values when the PQ backend is available | Authenticated signer identity: the packet currently carries the public key and a key ID derived from that key; without an external trust binding, this is self-asserted key material |
| TLS | Protects transport when correctly configured and certificate-validated | At-rest key custody, endpoint authorisation or a safe application-level trust-root change process |

A cryptographically valid receipt means the signed bytes verify against a
selected key and policy. It does not prove the tool action occurred exactly as
described, that the policy was appropriate, that the actor had wider business
authority, or that the action was safe or compliant.

## 2. Key classes and custody owners

| Key/material | Intended owner/custodian | Companion handling |
|---|---|---|
| Gate receipt signing private key (Ed25519) | Raucle gate operator / upstream signing service | Must never be imported, stored or backed up by Agent Assurance |
| Gate issuer public keys / trust roots | Trust-policy administrator, separate from routine analyst role | Public material only; preserve versioned history and verify provenance before activation |
| ML-DSA-65 packet private key (optional) | Packet-signing deployment owner | Current code accepts a caller-supplied key; no central KMS/HSM adapter is evidenced |
| ML-DSA-65 packet public key | External trust administrator / verifier trust policy | Embedded public key is not an identity trust anchor by itself |
| Ingest API credentials | Deployment operator / identity provider | Store outside source control; rotate/revoke through deployed identity control plane |
| Langfuse API keys, encryption key and salt | Reference deployment operator | Generated into external install `.env`; file mode 0600 documented; backup is operationally sensitive |

No production HSM or KMS integration is evidenced in this repository. Do not
claim HSM-backed, KMS-backed, FIPS-validated, hardware-isolated or centrally
managed key custody on this evidence.

## 3. Required lifecycle controls

### 3.1 Generation

- Generate private keys using an approved cryptographic library and operating
  system CSPRNG on a controlled host or managed key service.
- Record algorithm, key size/parameters, key ID, owner, purpose, creation
  timestamp, activation date and intended rotation interval.
- Generate production issuer keys outside developer workstations and CI.
- For HSM/KMS-backed deployment, generate or import only under the service's
  documented non-exportable-key policy; retain provider attestation and key
  policy evidence.
- Do not place private key bytes in source control, issue comments, CI logs,
  build artifacts or support tickets.

**Current evidence/gap:** the companion's optional packet API accepts a caller
supplied ML-DSA private key; tests generate ephemeral keys. This demonstrates
test-level signing, not a production key-generation service or hardware custody.

### 3.2 Storage and use

- Keep gate signing private keys in the upstream gate's isolated signing
  boundary. The companion should receive public trust roots only.
- Separate key administration from application deployment and evidence
  analysis. Use least-privilege identities, MFA for human administrators,
  dual approval for production trust-root changes and logged break-glass.
- Restrict private-key read/export; prefer signing operations that do not expose
  private key material to application memory.
- Encrypt backups and environment files at rest; tightly restrict access and
  monitor reads. Never store secrets in the evidence pack.
- Do not treat a PEM file with restrictive permissions as equivalent to
  non-exportable HSM/KMS custody.

**Current evidence/gap:** SECURITY.md excludes PEMs and env files from commits.
The reference deployment generates its own application secrets in an external
0600 `.env`. Neither fact proves the upstream gate signing key is hardware
protected or that production key access is centrally audited.

### 3.3 Trust-root publication and change

- Trust-root additions, retirement, revocation and validity-window changes
  require authenticated administrative approval, a change ticket and an
  append-only audit record.
- Distribute trust-root updates over an authenticated channel and protect the
  registry against rollback. Pin a trust-policy version or signed registry
  digest in every verification result.
- Preserve old public keys and their validity/revocation history for as long
  as receipts signed by them must remain verifiable.
- Distinguish compromise revocation from planned retirement. Record effective
  event time and discovery time; do not silently rewrite historical verdicts.
- Require two-person approval for emergency replacement of a production root.

**Current evidence/gap:** ADR-0001 specifies event-time verification and
versioned trust roots, and a demo JSONL trust-root fixture exists. This repo
does not demonstrate a production authenticated distribution, dual approval
or anti-rollback mechanism.

### 3.4 Rotation

- Establish a documented rotation interval and trigger-based rotation for
  suspected compromise, personnel changes, provider incidents or algorithm
  deprecation.
- Publish and validate the new public key before switching issuers; test both
  new issuance and historical verification.
- Keep the previous public key and status history. Confirm the verifier selects
  keys by key ID and event time, not simply current status.
- Record cutover time, affected issuer identity, key IDs, approvals and
  verification test results.

**Required acceptance test:** issue a test receipt before rotation and after
rotation; verify both offline against the archived trust-root history; confirm
that a receipt signed after the old key's effective revocation is rejected
according to the documented policy.

**Current evidence/gap:** ADR-0001 states the intended semantics. A complete
end-to-end production rotation drill is not evidenced here.

### 3.5 Revocation and compromise response

On suspected or confirmed private-key compromise:

1. Declare a security incident and identify the affected issuer/key ID and
   earliest plausible compromise time.
2. Stop or isolate use of the key through the upstream gate control plane.
3. Revoke/retire the key with an effective timestamp and publish the updated
   trust policy through the authenticated change process.
4. Generate and activate a replacement key under the generation procedure.
5. Preserve the compromised public key and history as revoked; never delete
   it or silently treat all historic signatures as trustworthy.
6. Identify receipts in the affected time window; re-verify and mark affected
   evidence with an explicit compromised-key status/findings record.
7. Notify affected customers and internal risk owners under contractual and
   legal incident procedures.
8. Record root cause, access logs, timeline, impact, remediation and lessons
   learned; run a post-incident review.

**Current evidence/gap:** ADR-0001 describes gate-time revocation and historical
verification constraints. No tested production compromise drill or
customer-notification runbook is evidenced in this repo.

### 3.6 Backup and recovery

- Back up the public trust-root registry, validity/revocation history, policy
  versions and evidence needed to re-verify historical receipts.
- Encrypt backups, restrict access, record digests and test restore into an
  isolated environment.
- Back up private key material only where policy and provider model require
  it; prefer provider-managed backup/recovery for non-exportable keys.
- For any exportable private key, require encrypted offline backup, split
  knowledge or equivalent dual control, documented recovery custodians and
  tested restoration. Never put private keys in the same archive as public
  evidence packs.
- Define RPO/RTO and ensure loss of the trust-root archive cannot silently
  downgrade historic receipts to unknown keys.

**Current evidence/gap:** OPS-01 proves backup/restore of the reference stack
volumes and receipt store, with checksums. The runbook does not establish a
tested backup/restore of the production trust-root registry or upstream private
signing key.

### 3.7 Destruction and decommissioning

- Destroy or cryptographically erase retired private keys only after approved
  retention and legal-hold requirements are met and recoverability is no
  longer required.
- Preserve public keys, key IDs, revocation records and trust-policy history
  for the evidence-retention period.
- Record destruction approval, method, date and verification evidence.
- Never delete public trust history merely because the corresponding private
  key has been destroyed.

## 4. Algorithm and verifier lifecycle

- Maintain an inventory of algorithms, library versions and protocol profiles
  used for receipt signing, packet signing, hashing and timestamp validation.
- Pin and review cryptographic dependencies; monitor upstream security
  advisories and algorithm deprecation.
- Keep verification fail-visible for unsupported algorithms, malformed
  signatures, missing keys and unavailable trust services.
- Run positive and negative conformance tests for signature, digest, key ID,
  algorithm mismatch, malformed encodings and tampering.
- Treat optional post-quantum packet signatures as an additional mechanism,
  not as a replacement for authenticated trust-root distribution.

**Repository evidence:** `tests/assurance_packet/test_packet_pq_signature.py`
tests digest binding, wrong key ID, wrong algorithm, malformed signature,
tampering and backend-unavailable cases. The module skips when the PQ backend
is unavailable. The public key is carried in the packet; external signer
identity binding is not provided by that field alone.

## 5. Control-to-evidence matrix

| Control | Existing evidence | Remaining acceptance evidence |
|---|---|---|
| Receipt byte integrity and Ed25519 verification | `tools/verifier/verify_pack.py`; `tests/verifier/test_verify_pack_tamper.py`; conformance fixtures | Independent crypto review and tests against production-issued receipts |
| Offline packet digest and receipt-chain revalidation | `tools/verifier/revalidate_packet.py`; verifier tests | External review of trust-root authenticity and verifier independence |
| PQ packet signature validation | `tests/assurance_packet/test_packet_pq_signature.py` | Trusted signer identity binding; production key custody; ensure CI exercises backend rather than skips |
| Versioned trust-root semantics | `docs/adr/0001-trust-model-and-evidence-plane.md`; demo trust-root fixture | Authenticated registry, anti-rollback, approval log and rotation/revocation integration tests |
| Secret exclusion and reference deployment env handling | `SECURITY.md`; `deploy/reference/README.md`; `ops/runbook.md` | Production secret-store policy, access audit, rotation and recovery evidence |
| Backup/restore of reference data | `ops/backup.sh`, `ops/restore.sh`, OPS-01 runbook | Trust-root archive restore drill and deployment-specific RPO/RTO |
| Key compromise response | This procedure (design only) | Named on-call owners, upstream gate runbook, tabletop and technical drill |
| HSM/KMS custody | No integration evidenced | Architecture decision, supported provider integration, policy evidence and independent validation |

## 6. Deployment decision record required before enterprise assurance

For each production deployment, record:

- signing service and key owner;
- algorithm and key IDs (never private key bytes);
- generation location and entropy source;
- custody boundary and whether keys are exportable;
- HSM/KMS provider, key policy and attestation if applicable (or explicit
  statement that no HSM/KMS is used);
- authorised principals, MFA, dual-control and access-log location;
- rotation interval, revocation propagation and historical verification
  behaviour;
- backup/recovery model, custodians, RPO/RTO and last restore test;
- trust-root distribution channel, approval and anti-rollback controls;
- incident contact, escalation and customer notification owner.

No deployment should be described as enterprise key-custody assured until
this record is complete and independently reviewed.
