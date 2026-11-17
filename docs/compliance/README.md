# Compliance packs (evidence mappings)

The raucle-agent-assurance evidence plane ships framework packs: mappings of
its offline-verifiable evidence (signed gate receipts, the receipt chain,
custody coverage, red-run findings) to the frameworks enterprise checklists
name. Every pack is a mapping in the "mapped to" sense only: each row says
what repository evidence exists and how far it goes, with an honest
SUPPORTED / PARTIAL / UNSUPPORTED verdict per control. No pack claims
compliance, certification or conformance for the repository or for any
deployment.

- [EU AI Act pack v1](eu-ai-act-pack-v1.md) - logging, transparency, human
  oversight, robustness (Articles 12, 13, 14, 15, 19, 50).
- [HIPAA Security Rule pack v1](hipaa-security-rule-pack-v1.md) - technical
  safeguards (164.312 audit controls, integrity, access control, transmission
  security).
- [PCI DSS pack v1](pci-dss-pack-v1.md) - logging, identity, configuration
  and secure development (Requirements 2, 6, 8, 10).
- [ISO/IEC 42001 pack v1](iso-42001-pack-v1.md) - AI management system
  clauses 4 to 10 and the Annex A records and operation controls.
- [NIST AI RMF pack v1](nist-ai-rmf-pack-v1.md) - GOVERN, MAP, MEASURE and
  MANAGE core functions, with the existing OWASP LLM Top 10 crosswalk slice
  noted alongside.

The machine-readable rows behind every pack live in the governance crosswalk
(`ops/assurance-profiles/crosswalk.json`); the deterministic, vendor-neutral
export is the `grc_evidence_graph/v1` document from
`tools/grc_export/export.py`. Pack-to-crosswalk consistency is enforced by
the tests in `tests/assurance/`, and packs are validated against governance
profiles by `ops/assurance-profiles/validator.py`.
