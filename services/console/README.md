# Raucle Console (EPIC-N)

Single-page application shell for the Raucle agent suite. The console is ONE
application; suite products are ADD-INS purchased separately:

- **Raucle Agent Trust** - gate / evidence core (capability cards plus a
  'connect your gate' pointer via env `RAUCLE_TRUST_GATE_CONFIG`).
- **Raucle Agent Assurance** - investigation add-in (LIVE); embedded in an
  alpha iframe pointing at the configurable env `RAUCLE_ASSURANCE_URL`
  (default `http://127.0.0.1:3411`). Served separately by its own process.
- **Raucle Agent Red** - wave 2, coming soon; announcing later.

Apache-2.0; no build toolchain (one HTML file, vanilla JS, `textContent`
only, threat-model T5). Semantic colour system: green proven / amber
un-proven / red action needed / grey exempt, with a visible legend.

## Tenancy

Single-tenant alpha: one tenant (`default`). Org identity is derived by the
server per the tenancy ADR contract; the console sets no cookies and accepts
no tenant input. Authenticated multi-tenancy is a later epic.

## Configuration (environment at start-up)

- `RAUCLE_ASSURANCE_URL` - iframe target for the Assurance add-in
  (default `http://127.0.0.1:3411`).
- `RAUCLE_TRUST_GATE_CONFIG` - documented (never displayed) pointer for
  connecting your gate to Raucle Agent Trust.

Environment values are never echoed in any API response.

## Run

    ../../.venv/bin/uvicorn raucle_console.app:app --app-dir src --port 3412
    # open http://127.0.0.1:3412/

## Tests

    ../../.venv/bin/pytest services/console/tests

Routes (`/`, `/api/overview`, `/api/config`, `/api/health`), iframe
configuration, textContent discipline scan, semantic colour legend and
alpha-placeholder guidance are all exercised with `TestClient`.