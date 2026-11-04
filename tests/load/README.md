# load — bounded steady-state smoke against the LOCAL reference stack

Previously reserved; OPS-01 adds the first occupant.

`load_smoke.py` generates steady-state traffic at 10 runs/sec x 20 spans
against the local reference stack (same `oaa.*` span shapes as
examples/reference-agent), with a 30 s no-export baseline, and writes a report
(default `ops/scratch/load-report.json`). It is a smoke, not a benchmark:
single host, batch export (`max_export_batch_size=512`), producer per-run
wall-clock p95 vs baseline p95.

```bash
.venv/bin/python tests/load/load_smoke.py \
  --env /home/craigamcw/oaa-reference-stack/.env \
  --out ../ops/scratch/load-report.json
```

The env file needs `OAA_LF_PUBLIC_KEY` / `OAA_LF_SECRET_KEY` (install.sh writes
them into the install `.env`). Profile overridable (`--rate`, `--duration`,
`--baseline-duration`). Recorded results: docs/spikes/OPS-01-findings.md §5.
Do NOT run this against remote/production stacks.
The planned full load suite arrives with the Open Agent Assurance build-out.