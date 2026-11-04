# EPIC-N findings: Raucle Console application shell

Status: alpha. One FastAPI service (`services/console`, port 3412) serving a
single-page shell; no build toolchain; vanilla JS with textContent-only
rendering (threat-model T5 carried over from investigation-ui).

## Architecture: shell plus add-ins

- The console is ONE application. Suite products are add-ins purchased
  separately and listed in a catalogue (`/api/overview.addins`):
  Raucle Agent Trust (wave 1), Raucle Agent Assurance (wave 1, LIVE),
  Raucle Agent Red (wave 2, not started).
- Add-in status chips reuse the semantic colour system: Connected (green),
  Degraded (amber, add-in offline), Not purchased (grey).
- Trust counters shipped with the console are embedded demo-data counts
  sourced from the pinned investigation-ui fixture set (9 receipts minted,
  10 verification rows, 5 valid). They refresh when Trust exposes a counts
  endpoint; deliberately no proxying in the alpha.
- Assurance traffic-light counters are fetched BY the SPA from the console's
  own `/api/assurance/dashboard` endpoint, which proxies the add-in's
  `/api/dashboard` (the add-in sends no CORS headers in alpha, so a direct
  cross-origin fetch is impossible). Failure is an explicit 503 rendering a
  graceful 'add-in offline' empty state; the console never aggregates or
  caches add-in data server-side.

## Tenancy

Single-tenant alpha with one tenant (`default`). Org identity is server
derived per the ADR tenancy contract; the console holds no session, cookie
or tenant-selection state, and `/api/config` exists to carry client config
(add-in URLs) without ever echoing environment secrets.

## Iframe embed (alpha path) vs plugin registry (future)

- The Assurance add-in is embedded as an iframe to `RAUCLE_ASSURANCE_URL`
  (default `http://127.0.0.1:3411`). This is acceptable for alpha because:
  (a) the add-in is a separate, independently deployable process;
  (b) the console adds no new attack surface over browsing the add-in
  directly; (c) it avoids a plugin ABI commitment in wave 1.
- Known limits: the iframe cannot share the shell's future auth context,
  deep-link state syncs only via URL, and the shell cannot style the
  add-in's content (by design, same-origin policy).

## Security notes (iframe/CSP plan)

- **X-Frame-Options must NOT block our own embed**: the Assurance add-in at
  3411 must not send `X-Frame-Options: DENY/SAMEORIGIN` for console origins,
  or set `frame-ancestors` accordingly. Today it sends neither, verified by
  fetching `/` with curl (no frame-blocking headers present).
- CSP plan (when headers are added): console page sets
  `frame-src 'self' http://127.0.0.1:3411` (config-driven), the add-in sets
  `frame-ancestors` to the console origin. No wildcard ancestors.
- SPA discipline (tested): no `innerHTML`/`outerHTML`/`insertAdjacentHTML`/
  `document.write`/`eval`; every external URL in the page must be
  `http://127.0.0.1:*` in the alpha; the only cross-origin fetch is the
  configured add-in origin, shown in place to the operator.
- Environment values are never echoed by any endpoint (tested).

## What is intentionally NOT done

- No ufw/firewall changes (parent handles).
- No authentication, multi-tenancy or persistence: the tenant stubs
  (Settings, Profile, Notifications) are clearly banner-marked alpha
  placeholders and save nothing.
- No pricing tiers shown in product UI: wording is 'Included with licence
  key'.

## Roadmap

1. Wave 1 completion: Trust counts endpoint and live gate connect via
   `RAUCLE_TRUST_GATE_CONFIG`.
2. Plugin registry replacing the iframe: in-process add-ins with a minimal
   manifest (id, capabilities, mount point), shared auth context, same
   textContent discipline enforced at mount time.
3. Authenticated multi-tenancy per the ADR contract; server-derived org
   identity stays the single source of tenancy truth.
4. Notifications sourced from an events plane rather than `/api/overview`
   demo items; profile from an operator directory.