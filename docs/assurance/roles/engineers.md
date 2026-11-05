# Agent assurance for engineers

Audience: engineers building and operating the assurance tooling the roles
above rely on. All artefacts referenced exist in the repository today;
planned work is marked planned and tracked in the overnight sprint backlog.

## The daily loop

```bash
.venv/bin/python -m pytest tests/ -q
```

The project venv carries pytest, ruff and jsonschema. Lint and format before
you commit:

```bash
.venv/bin/ruff check . && .venv/bin/ruff format .
```

The local gate bundles both plus security scanning with the committed
configuration: `scripts/local-gate.sh`.

## Key artefacts, by area

Audit pack: `scripts/build_audit_pack.py` builds the pack; verification
lives in `tools/verifier/verify_pack.py`; tamper expectations are pinned by
`tests/verifier/test_verify_pack_tamper.py`. The recorded clean run and the
deliberate-tamper RED path are documented in `docs/demo/demo-run-4nov.md`.

Run records: the schema is `schemas/agent_run_record.schema.json`; the
fixture generator is `tools/run_records/generate_fixtures.py`, run with the
project venv (see `schemas/README.md` for the exact invocation). Tests:
`tests/conformance/test_agent_run_record.py`. Rule 3 applies to anything you
touch: never infer `valid` (or `allow`) from missing data; keep `unknown`
distinct.

Security tests: redaction is tested in `tests/security/test_redaction.py`;
the PRV-01 style live probe is `tests/security/test_priv01_live.py` (its
fixtures are deliberate detector bait — do not clean them up).

Demo data: the committed investigation demo fixtures live in
`services/investigation-ui/demo_data/`. Synthetic rows are hand-built demo
artefacts (marked `synthetic: true`), never canonical evidence; keep that
marker intact when you extend fixtures.

Reference agent: `examples/reference-agent/reference_agent.py` plus the
probe scripts in the same directory.

## Docs engineering

Role documents under `docs/assurance/roles/` are aligned-checked. After
editing any of them (or any artefact they name) run:

```bash
.venv/bin/python scripts/check_docs_alignment.py
```

It fails with a `FAIL` line per reference that no longer resolves. If you
rename or move an artefact, fix the role documents in the same commit.

## Working agreements

- Commit messages state the behaviour, not the intention.
- Optional dependencies (raucle, z3) must degrade to SKIP or honest notes,
  never silent pass: see `conftest.py` and the raucle skip rationale in
  `pyproject.toml`.
- No secrets are committed; local service credentials go into git-ignored
  env files (`deploy/compose/langfuse.env.example` documents the variable
  names).
