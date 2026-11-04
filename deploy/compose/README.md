# deploy/compose — Langfuse v4.74.0 self-hosted

Adapted from the upstream Langfuse v4.74.0 docker-compose.yml and pinned to
`4.74.0` images. Secrets are NOT in this file: every credential is a
`${VAR}` placeholder filled from a local env file:

```bash
cp langfuse.env.example langfuse.env   # then fill in real values locally
docker compose --env-file langfuse.env up -d
```

`langfuse.env` is git-ignored (`*.env` in .gitignore). Never commit it.

Deployment notes carried over from the OBS-01 spike:
- Only langfuse-web (127.0.0.1:3301) and ClickHouse debug ports bind to
  localhost; other services are internal-only.
- v4.74.0 self-host defaults `LANGFUSE_MIGRATION_V4_WRITE_MODE=events_only`,
  which 404s the legacy read API — this compose file sets `dual`
  (recorded in ADR-0003).