# Threat model v1 — Agent Assurance companion

**Status:** Engineering review draft; independent security review is still required  
**Owner:** Product/security owner (to be assigned formally)  
**Last updated:** 2026-11-25  
**Supersedes:** `docs/threat-model/threat-model-v0.md` as the current review baseline; v0 is retained as historical input.

## 1. Scope and assurance boundary

This model covers the Agent Assurance companion, its ingestion, evidence storage,
verification, indexing, operator interface, packaged reference deployment and
exported assurance packs. It considers the Raucle gate and its signing service
as an upstream trust dependency, not as a component whose implementation or
production deployment is independently audited by this repository.

The companion is not the enforcement authority. It observes and verifies
evidence; it must not grant, revoke or silently alter gate permissions. A
successful signature or receipt-integrity check proves only that the signed
bytes verify under the selected trust root and recorded policy. It does not
prove that the underlying business action was safe, authorised in the wider
business context, correctly executed, or compliant.

This is an engineering threat-model update, not an independent penetration
test, cryptographic review opinion, certification or production deployment
attestation.

## 2. System, assets and security objectives

| Asset | Security objective | Primary consequence of compromise |
|---|---|---|
| Gate signing private key and issuer identity | Confidentiality and controlled use | Forged receipts attributed to a trusted issuer |
| Trust-root registry and history | Integrity, authenticity, availability | Attacker can make forged evidence appear trusted or make valid history unverifiable |
| Canonical receipt bytes and JWS | Integrity, provenance, durable availability | Evidence alteration, deletion or fabricated history |
| Evidence-pack manifest and exported files | Integrity and completeness | Misleading or incomplete assurance pack |
| Producer credentials and ingest identity | Confidentiality, integrity | Telemetry spoofing, cross-tenant injection or evidence loss |
| Telemetry and correlation metadata | Confidentiality and integrity | Sensitive data disclosure or false correlation |
| Rules, configuration and suppression records | Integrity and accountability | Detection silently weakened |
| Analyst/admin credentials and sessions | Confidentiality, least privilege | Evidence disclosure or trust-policy manipulation |
| Signing/verification dependencies and build pipeline | Integrity and provenance | Compromised cryptographic or verification code |
| Backups, environment files and recovery material | Confidentiality, integrity, availability | Key loss, service outage or secret disclosure |

Security objectives: preserve canonical bytes; verify against an authenticated,
versioned trust policy; fail visibly on unknown or unavailable evidence; keep
enforcement separate from monitoring; prevent unauthorised key and policy
changes; preserve confidentiality of telemetry and secrets; and make recovery
and incident actions auditable.

## 3. Trust boundaries and data flows

1. **Agent/runtime → gate:** the runtime is untrusted. Gate-side authorisation
   and receipt creation are upstream controls. Companion telemetry cannot
   establish that every tool path was observed.
2. **Agent/collector → ingest API:** producer credentials and transport protect
   identity and channel; payload fields remain attacker-controlled. Organisation
   identity must be derived server-side, not trusted from payload content.
3. **Gate receipt → evidence sink:** receipt bytes cross a network/storage
   boundary. The evidence plane stores canonical envelopes; the index is
   derived and must never replace the original bytes.
4. **Evidence bytes + trust roots → verifier:** verification depends on the
   authenticity, completeness and temporal semantics of the trust-root
   registry, verifier implementation and cryptographic libraries.
5. **Evidence plane → index/correlation/rules:** derived records can be stale,
   missing, duplicated or ambiguous. Unknown/unavailable states must not become
   valid by default.
6. **Analyst/admin → console and configuration:** user input, model output,
   trace content and imported evidence are hostile. Privileged actions require
   separately authenticated and authorised roles.
7. **Build/release → deployed service:** source, dependencies, workflow actions,
   container images and release artefacts form a software supply-chain boundary.
8. **Deployment → backup/restore:** environment files, data volumes, public
   trust roots and any separately held private signing material must be handled
   under distinct custody and recovery procedures.

## 4. Threat scenarios and control/evidence mapping

| ID / threat | Mitigations and current evidence | Residual risk / required follow-up |
|---|---|---|
| TM-01: compromised agent fabricates, alters or omits telemetry | Producer identity and server-side tenant derivation are specified in v0; signed gate trace ID is authoritative when present; SEC-001/004 rules and independent-vantage matrix cover discrepancies | Uninstrumented or never-gated paths remain invisible. Verify deployed ingest authentication and tenant isolation; add live negative tests |
| TM-02: credential theft or replay at ingest | Authenticated producer identity, TLS and replay-resistant ingest are design requirements | Deployment-specific credential issuance, expiry, rotation and revocation evidence is incomplete; add operational proof and abuse tests |
| TM-03: receipt bytes altered or forged | JWS/Ed25519 verification and receipt-hash recomputation; `tools/verifier/verify_pack.py`; tamper tests in `tests/verifier/test_verify_pack_tamper.py` and conformance fixtures | Verification is only as trustworthy as the selected public-key trust anchor and verifier/build. Independent crypto review and key provenance evidence required |
| TM-04: trust-root substitution or rollback | ADR-0001 specifies versioned roots, event-time selection and trust-policy version recording; demo trust-root fixture exists | Production registry authentication, approval workflow, anti-rollback protection and independent change monitoring are not demonstrated in this repo |
| TM-05: signing-key compromise | Separation of private signing keys from companion; SECURITY.md forbids committing PEMs; key lifecycle requirements in key-custody document | Upstream gate key storage, KMS/HSM use, access logging, rotation and compromise drill are not evidenced here; obtain upstream architecture and operational evidence |
| TM-06: key loss or premature retirement | ADR-0001 and verifier pack format preserve historical public-key snapshots; backup/runbook covers service volumes and receipt store | Trust-root archive backup/restore and integrity verification are not fully automated or tested as a distinct critical asset |
| TM-07: malicious or compromised analyst/admin | v0 identifies role separation and hostile rendering; console and access controls require deployment review | No independent authorisation/SSO/MFA assessment in this task; validate actual production role boundaries and audit trails |
| TM-08: evidence sink, index or verifier unavailable | ADR-0001 requires fail-visible `unavailable` states; SEC-007; OPS-01 backup/restore and recovery runbook | Live resilience, RPO/RTO and backup restore drills must be evidenced for each deployment; reference-stack evidence is not production assurance |
| TM-09: suppression/config tampering | Versioned YAML rules/config; narrow suppression matching and retained suppression reason in findings | Config signing/approval, immutable change history and deployment drift detection require operational controls |
| TM-10: telemetry or secret leakage | PRIV-01 seeded-secret redaction tests and metadata-only default documented in `tests/security/README.md` | Live proof is local-stack scoped; production retention, access, residency and tenant isolation need separate assessment |
| TM-11: malicious assurance-pack input / path traversal | Standalone verifier performs zip-slip-safe extraction and manifest/hash checks; verifier tamper tests | Fuzzing, resource-exhaustion limits and independent review of parser dependencies remain open |
| TM-12: build/dependency compromise | CI, Sonar and the proposed SBOM/dependency-audit workflow in PR #93 | PR #93 remains unmerged as of this revision; pinning third-party actions by immutable SHA and release provenance remain follow-ups |
| TM-13: monitoring plane gains enforcement authority | Structural separation in ADR-0001; companion consumes evidence and produces findings only | Reconfirm with architecture tests and deployed permissions; no companion service account should have gate policy-write privileges |
| TM-14: PQ packet signature misrepresented as signer authentication | ML-DSA-65 signature verification tests cover digest binding and malformed/tampered signatures | Current packet embeds its public key and derives key_id from it; absent an independently trusted key binding, this proves possession of the corresponding private key, not an identified/authorised signer. Do not market as authenticated organisational signature |

## 5. STRIDE summary

- **Spoofing:** forged producer identity, receipt issuer or trust root. Controls:
  authenticated ingest, signed receipt verification and independently
  administered trust roots. Deployment evidence and trust-root approval are open.
- **Tampering:** altered receipts, manifests, rules or trust policy. Controls:
  JWS verification, content hashes, manifest verification, immutable evidence
  storage and narrow configuration changes. Operational immutability and
  privileged-change monitoring require proof.
- **Repudiation:** denial of key or policy changes, receipt issuance or evidence
  deletion. Controls: signed receipts, timestamp references, change records and
  preserved trust history. A complete independently protected admin audit trail
  is not demonstrated.
- **Information disclosure:** telemetry, credentials, signing keys and backup
  leakage. Controls: metadata-first redaction, TLS, least privilege and secret
  exclusion. Production access and retention settings require review.
- **Denial of service:** invalid receipt floods, storage exhaustion, ingest
  outage or verifier resource exhaustion. Controls: bounded payloads, rate
  limits, fail-visible unavailable state and recovery procedures. Capacity
  limits and adversarial load tests remain deployment-specific.
- **Elevation of privilege:** analyst/admin compromise, build pipeline abuse or
  companion gaining gate authority. Controls: role separation and structural
  enforcement boundary. SSO/MFA, approval controls and CI provenance need
  independent validation.

## 6. High-priority risks and release gates

The following remain P0/P1 assurance gates until evidenced for the target
deployment:

1. Obtain the gate issuer's production key-management architecture: generation,
   custody boundary, access roles, audit, rotation, revocation and compromise
   response.
2. Authenticate trust-root distribution and administrative changes; protect
   against rollback and unauthorised key insertion.
3. Demonstrate trust-root archive backup/restore and historical receipt
   verification across a real rotation.
4. Demonstrate producer credential lifecycle and tenant isolation with
   negative integration tests.
5. Obtain independent cryptographic design review and penetration testing.
6. Pin third-party workflow actions and produce release-linked SBOM/provenance.
7. Exercise production-like restore and incident procedures with measured RPO
   and RTO.

## 7. Review record and limitations

- Engineering source review: performed for this document against the repository
  files linked above on 2026-11-25.
- Independent security reviewer: **not yet assigned / not yet signed off**.
- Production key custody: **not verified by this repository review**.
- HSM/KMS: **no production HSM/KMS integration evidenced in this repository**.
- Penetration test: **not performed by this document or its author**.

A reviewer must record name, organisation, independence from feature authors,
date, scope, artefacts reviewed, findings, severity, disposition and signature.
Do not mark issue #89 complete until that independent review is recorded.
