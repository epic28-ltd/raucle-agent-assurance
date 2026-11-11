# Contributing

Status: alpha, in progress. The API surface of the adapter packages is not
stable yet, and no compatibility promises are made before 0.1.0.

## Ground rules

1. Apache-2.0 for all code; every source file carries the
   `# SPDX-License-Identifier: Apache-2.0` header.
2. Local commits are signed-off (`git commit -s`) and kept small: one intent
   per commit; `git log --stat` must read back cleanly.
3. `ruff format` and `ruff check` must pass on every change; the raucle-free
   pytest set must pass (raucle-dependent tests may SKIP when raucle is not
   installed — that is the expected CI state until the environment ships).
4. The ADR design invariants are binding (docs/adr). Behaviour that weakens
   them (mutating canonical evidence, inferring `valid` from missing data,
   treating correlation as authentication, deleting retired trust roots) is a
   review rejection by definition.
5. Conformance fixture changes are generated through
   `oaa_raucle_adapter.fixture_gen` against the pinned raucle distribution —
   never hand-constructed JWS artefacts.
6. Enterprise-shaped contributions (fleet consoles, multi-tenant operator
   tooling, commercial connector work) live in the Enterprise Edition, a
   separate closed repository, not here. Raise them as a discussion issue
   first so they land in the right edition. Fixes, adapters, backends,
   verifier improvements and compliance mappings all belong here and stay
   Apache-2.0.

## Layout discipline

New services go under `services/`, integrations under `integrations/`,
trace backends under `integrations/backends/`, deployment manifests under
`deploy/compose/`. Spike records and findings docs live under `docs/spikes/`
and are historical records, not product documentation.

## Local development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install pytest ruff
PYTHONPATH=packages/raucle-adapter/src pytest tests/ -rs
ruff format --check . && ruff check .
```

raucle (optional, needed only for signature-verification tests):
see packages/raucle-adapter/README.md.
