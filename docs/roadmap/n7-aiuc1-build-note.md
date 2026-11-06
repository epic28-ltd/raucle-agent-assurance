# N7 build note — AIUC-1 crosswalk rows + workpaper export

## Source of the control list

No pinned AIUC-1 material was on disk in this clone, so the rows were derived
from the AIUC-1 published framework headings on standard.aiuc-1.com (fetched
2026-11-06). Each row cites its source heading text verbatim in
`source_heading`, quotes the requirement text verbatim in `control_text`, and
carries `"derivation": "derived"`.

Verbatim requirement headings used (AIUC-1, standard.aiuc-1.com):

- `E001: AI failure plan for security breaches` — https://standard.aiuc-1.com/accountability/ai-failure-plan-for-security-breaches
- `E004: Assign accountability` — https://standard.aiuc-1.com/accountability/assign-accountability
- `E009: Monitor third-party access` — https://standard.aiuc-1.com/accountability/monitor-3rd-party-access
- `E015: Log AI system activity` — https://standard.aiuc-1.com/accountability/log-model-activity
- `E018: Third-party testing for accountability risk` — https://standard.aiuc-1.com/accountability/3rd-party-testing-for-accountability-risk
- `D001: Prevent hallucinated outputs` — https://standard.aiuc-1.com/reliability/prevent-hallucinated-outputs
- `D003: Restrict unsafe tool calls` — https://standard.aiuc-1.com/reliability/restrict-unsafe-tool-calls
- `D004: Third-party testing for reliability risk` — https://standard.aiuc-1.com/reliability/3rd-party-testing-of-tool-calls

Requirement family pages (heading text also quoted per row):

- `E. Accountability` — https://standard.aiuc-1.com/accountability
- `D. Reliability` — https://standard.aiuc-1.com/reliability

## Verbatim control text quoted into crosswalk.json (`control_text`)

- E001: "Document AI failure plan for AI privacy and security breaches
  assigning accountable owners and establishing notification and remediation
  with third-party support as needed (e.g. legal, PR, insurers)."
- E004: "Document which AI system changes across the development & deployment
  lifecycle require formal review or approval, assign a lead accountable for
  each, and document their approval with supporting evidence."
- E009: "Implement systems to monitor and log third-party API connections,
  sessions, and data access."
- E015: "Maintain logs of AI system processes, actions, and agent outputs
  where permitted to support incident investigation, auditing, and
  explanation of AI system behavior."
- E018: "Appoint expert third-parties to evaluate system robustness to
  accountability risk as defined in the AIUC-1 risk taxonomy at least every
  3 months"
- D001: "Implement safeguards or technical controls to prevent hallucinated
  outputs."
- D003: "Implement safeguards or technical controls to prevent tool calls in
  AI systems from executing unauthorized actions, accessing restricted
  information, or making decisions beyond their intended scope."
- D004: "Appoint expert third-parties to evaluate system robustness to
  reliability risk as defined in the AIUC-1 risk taxonomy at least every
  3 months"

All eight quoted verbatim from the published requirement pages listed above
(© AIUC — ALL RIGHTS RESERVED; quoted for truthful crosswalk mapping, not
paraphrased into invented controls). Note: E002/E003 (failure plans for
harmful outputs / hallucinations) were considered and folded into the E001
gap statement; D002 is retired per the standard's Q4 2026 changelog and is
deliberately not crosswalked.

## Statuses, honestly, against shipped machinery

- SUPPORTED rows cite packet fields the shipped gate/receipt chain actually
  fills (E015: receipt hashes, tamper-evident, re-verified offline by
  ops/audit-pack; D003: gate policy proofs + capability chain + coverage map,
  fail-visible via SEC-001/SEC-006).
- PARTIAL rows name the packet field that carries part of the answer and say
  what is missing in `basis`.
- UNSUPPORTED rows (E001, E018, D001, D004) cite no evidence field and state
  the gap in `unsat_reason`. Nothing in the evidence plane produces failure
  plans, appointments of expert third-parties, quarterly third-party
  evaluation, or hallucination-prevention safeguards today.
