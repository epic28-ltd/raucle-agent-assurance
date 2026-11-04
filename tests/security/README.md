# security

PRIV-01 redaction controls and the seeded-secret leak proof.

## Layout

- `test_redaction.py` — table-driven redaction unit tests (patterns, allowlist
  passthrough, entropy bounds, collector scan/quarantine). Runnable in bare
  CI without the trace stack or otel (otel cases `importorskip`).
- `test_priv01_live.py` — the skippable P0 acceptance test: emits a fixture
  trace twice (leaky / protected) against the LOCAL Langfuse only, and
  asserts on live API readback that (a) without redaction every seeded secret
  persists, (b) with the processor installed every seeded secret is absent and
  the collector scan is clean. Skips unless `OAA_PRIV01_LF_ENV_FILE` points
  at the stack env file AND the stack is reachable — no network beyond
  `http://127.0.0.1:3301`.
- `fixtures/seeds/` — the deterministic seeded-secret generator and its
  committed output (`seeds.json`, 9 seeds; re-running the generator is a
  no-op). All values are synthetic (`oaa-priv01-` / fake-PEM shapes).
- `fixtures/leak_harness.py` — the leaky/protected fixture emitter and the
  readback scanner (plain `urllib`, no non-otel runtime deps beyond
  `opentelemetry-sdk`, pinned at 1.45.x in the repo venv).
- `fixtures/run-artifacts/` — redaction-safe live proof artifacts (trace ids,
  collector summaries, redaction-token counts; seed values never included).

## Secrets

No real credentials are committed here. The stack env file lives outside the
repo and is only referenced through `OAA_PRIV01_LF_ENV_FILE`.