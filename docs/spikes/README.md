# docs/spikes — spike records

**These are historical spike records, not product documentation.** They
capture what was tested, against which pinned versions, on 4 Nov 2026
(EPIC K discovery), with expected-vs-actual results and effort estimates.
Normative design lives in `docs/adr/` and `docs/threat-model/`.

| Doc | Story | Verdict |
|---|---|---|
| DISC-02-findings.md | DISC-02 correlation spike | go gate cleared |
| backend-capability-matrix.md | DISC-01 | input to ADR-0003 |
| EVD-findings.md | EVD-01/02 evidence-plane spike | PASS both |
| OBS-01-findings.md | OBS-01/02 observability vertical slice | PASS |
| OPS-01-findings.md | OPS-01 packaged reference deployment (fresh install, restart/restore round-trip, load smoke) | PASS (install + restore + load verified) |
| workstreams-C-D.md | research workstreams C+D (trace semantics, instrumentation maturity, raucle trust model) | findings |

Related artefacts imported into the repo: evidence harness in
`packages/raucle-adapter` (core module, fixture generator, `examples/run_evd.py`
with run artifacts in `examples/run-artifacts/`), reference agent and probes
in `examples/reference-agent/`, Langfuse compose in `deploy/compose/`, fixture
corpus in `tests/conformance/`. OPS-01 packaging: `deploy/reference/`,
install script + runbook in `ops/`, load smoke in `tests/load/`.