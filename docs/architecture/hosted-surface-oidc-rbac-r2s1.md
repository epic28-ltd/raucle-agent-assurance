# Hosted-surface auth: org OIDC SSO + role ladder (R2 slice 1)

Status: implemented (optional feature, OFF by default).

The governing pattern is the raucle gateway's admin-plane identity
federation: `docs/spec/admin-identity-federation-x3s1.md` in the
`epic28-ltd/raucle` repository (read from origin/main; not paraphrased
here on purpose — this document describes how the HOSTED surfaces, the
console and the investigation UI, adopt that idiom in this repository's
architecture).

## Purpose

Let a hosting organisation's console operators authenticate THROUGH their
own OpenID Connect identity provider into the hosted operator surfaces
(the suite console and the investigation UI), with short-lived receipted
sessions and a role ladder enforced at route level — replacing the
previous single implicit operator model (every caller was every role on
an open alpha surface).

## What each surface gains

Both `services/console` and `services/investigation-ui` share one
machinery package: `oaa_hosted_auth` (physically under
`services/investigation-ui/src`, imported by the console through the
same cross-service `sys.path` idiom the shared counting module uses).

| Concern | Where |
| --- | --- |
| env contract + validation | `oaa_hosted_auth/config.py` |
| discovery / PKCE / exchange / id_token verify | `oaa_hosted_auth/federation.py` |
| sessions (issue/refresh/close, digest-only store) | `oaa_hosted_auth/sessions.py` |
| role ladder + registry (env grants + receipted changes) | `oaa_hosted_auth/rbac.py` |
| hashed receipt ledger (session + role lifecycle) | `oaa_hosted_auth/ledger.py` |
| FastAPI composition (binding, dependencies, routes, default-deny net) | `oaa_hosted_auth/hosted.py` |

## Configuration contract (env only; OFF by default)

| Setting | Env | Notes |
| --- | --- | --- |
| enabled | `OAA_HOSTED_OIDC_ENABLED` | `1`/`true`/`yes` enable; `0`/`false`/`no` disable |
| issuer | `OAA_HOSTED_OIDC_ISSUER` | must be `https://` |
| client id | `OAA_HOSTED_OIDC_CLIENT_ID` | required when enabled |
| console callback | `OAA_HOSTED_OIDC_REDIRECT_URI_CONSOLE` | e.g. `https://<host>:3412/` |
| assurance callback | `OAA_HOSTED_OIDC_REDIRECT_URI_ASSURANCE` | e.g. `https://<host>:3411/` |
| scope | `OAA_HOSTED_OIDC_SCOPE` | default `openid profile email` |
| secret | `OAA_HOSTED_OIDC_CLIENT_SECRET` | env ONLY, never a config file |
| secret file | `OAA_HOSTED_OIDC_CLIENT_SECRET_FILE` | path to a mode-0600 file |
| session ttl | `OAA_HOSTED_SESSION_TTL` | seconds, >= 60, default 3600 |
| session cap | `OAA_HOSTED_SESSIONS_MAX` | default 64, cap refuses fail-closed |
| state dir | `OAA_HOSTED_STATE_DIR` | receipted-ledger home (default: the service's own `.hosted-state/`) |
| viewer grants | `OAA_HOSTED_ROLE_VIEWER` | comma-separated identities |
| operator grants | `OAA_HOSTED_ROLE_OPERATOR` | comma-separated identities |
| security grants | `OAA_HOSTED_ROLE_SECURITY_ADMIN` | comma-separated identities |

A grant entry matches a verified principal when ANY of its identity
strings (the token's `sub`, `email`, `preferred_username` or `name`
claim) equals the entry — so an operator can grant by email before the
first login, and the IdP's stable subject is authoritative afterwards.

Fail-closed rules the config layer enforces at boot:

- an enabled surface with a missing/invalid issuer, client id, redirect
  URI or secret REFUSES to start (the composition root refuses with it;
  no half-open login exists);
- the secret never comes from a config document — env or a mode-0600
  file only (a looser file is refused, not read);
- a malformed enable flag is a configuration error, not a silent guess.

## Behaviour (matching the gateway idiom)

1. **Boot.** On enable, discovery is fetched from
   `{issuer}/.well-known/openid-configuration` at start-up; issuer
   identity is checked exactly (RFC 8414 3.3); every endpoint must be
   https; the JWKS must carry a usable RSA signing key. Any failure
   refuses the surface. A boot banner logs the enabled provider.
2. **Login.** `GET /api/oidc/login` builds the authorization URL:
   `response_type=code`, PKCE S256, single-use `state` + `nonce` held at
   most 5 minutes. `POST /api/oidc/callback` exchanges the code
   (client_secret_post) and verifies the `id_token`: RS256 against the
   JWKS by `kid`, strict `iss`/`aud`/`exp`/`nbf`/`nonce`. Any violation
   is a named error (`OIDC_EXCHANGE_ERROR`, `OIDC_CONFIG_ERROR`,
   `OIDC_DISCOVERY_ERROR`) and NO session is minted on doubt.
3. **Sessions.** `oas_`-prefixed 256-bit bearer tokens; only the SHA-256
   digest is stored. TTL enforced on every resolve; the session cap
   refuses fail-closed; expiry/malformed/unknown tokens are exactly like
   a missing header. Open / refresh / close are RECEIPTED in the hashed
   ledger (public hash-derived session handle, never the token).
4. **Roles.** The ladder is `viewer < operator < security-admin`
   (rank-min on contradictory grants; unknown identities default to
   `viewer` — view-only). The permission matrix binds every route in
   both surfaces to a capability (`read` / `write` / `security` /
   `session` / `public`); a matrix-completeness test walks both apps in
   CI so a future route without a capability fails the build. A
   default-deny net additionally refuses any request path the app never
   bound, fail-closed, for every caller.
5. **Role changes.** `POST /api/roles/{subject}` (security-plane:
   security-admin only) grants or revokes a role with a REQUIRED
   reason. The change is receipted into the hashed ledger (action,
   subject, role, reason, acting session handle) and takes effect on the
   next request of every open session. Boot replays env grants first,
   then receipted changes in ledger order, so a runtime grant survives a
   restart and an env re-assertion reverts drift. A role change whose
   receipt cannot be written is refused (503) and takes no effect.

## Route-level matrix (as bound in `create_app`)

Console (shell-only routes exempt: `/`, `/static/*`; `/api/health`
public):

- read (viewer+): `/api/overview`, `/api/config`,
  `/api/trust/policies/summary`, `/api/assurance/*` proxies,
  `/api/trends`, `/api/red/dogfood|targets|status|results`;
- write (operator+): `/api/red/run`, `/api/red/stop`,
  `/api/assurance/findings/ingest`;
- security: `POST /api/roles/{subject}`; read: `GET /api/roles`;
- session (any role): `/api/session/*`, `/api/oidc/*` (login + callback
  public).

Investigation UI (shell-only routes exempt: `/`, `/legacy.html`,
`/view/fleet`):

- read (viewer+): `/api/runs`, `/api/runs/{id}`, `/api/dashboard`,
  `/api/counts`, `/api/findings`, `/api/findings/red`,
  `/api/findings/board`, `/api/receipts/*`, `/api/live/traces`,
  `/coverage/{org}`, `/assurance/packet`, `/assurance/summary` and the
  no-JS `/view/*` pages (those fail closed as an HTML login page rather
  than leaking data);
- write (operator+): findings ingest, findings triage,
  `/api/fleet/rollup` POST + DELETE;
- session/security routes as above (shared implementation).

## Browser surface behaviour

One inline hook per SPA (console page, investigation pages, fleet view;
kept inside the files' existing script discipline):

1. interposes same-origin fetches so `/api|/coverage|/assurance` calls
   carry the session bearer from `sessionStorage` (tab-scoped; never
   localStorage, never a cookie);
2. captures the IdP redirect (`?code=...&state=...`) and exchanges it at
   `POST /api/oidc/callback` — a failed exchange leaves the shell empty
   and honest (fail-closed);
3. probes `/api/session/config` (public) and, with OIDC enabled and no
   valid session, navigates to `/api/oidc/login`.

## Honest limits, recorded deliberately

- The hosted surfaces hold no gateway signer in-process, so receipts here
  are tamper-evident hash-chained ledger entries in the surface's own
  sidecar (`hosted-<surface>-ledger.jsonl`, chain-verified on load and on
  boot) rather than JWS envelopes signed by the Trust gateway. Wiring a
  signer (and a receipt sidecar accepted by the offline verifier) is the
  named follow-up.
- The two surfaces keep INDEPENDENT sessions in slice 1: embedding the
  investigation UI in the console iframe authenticates separately, so a
  privileged org login happens once per surface. A shared cookie domain
  or gateway-brokered session is a later epic (authenticated
  multi-tenancy already is one).
- Role management is per-surface (each keeps its own receipted ledger);
  shared authority in a deployment comes from the env grant lists, which
  are authoritative at every boot.
- Auto-generated API docs (`/openapi.json`, `/docs`, `/redoc`) remain
  reachable in enabled mode because they carry the route registry itself
  (no data); refusing them under auth is a named follow-up decision.
- There is no key-based login on the hosted surfaces (the gateway keeps
  its own user records; the hosted surface has no local user store in
  this slice): sessions open only through the org's IdP.

## Tests

`tests/services/test_hosted_auth.py` (sessions, federation, config,
ledger) and `tests/services/test_hosted_rbac.py` (route-by-route
matrices for both surfaces, role lifecycle, fail-closed posture) run in
CI's raucle-free set: sessions, OIDC, RBAC and the ledger are all
offline-deterministic with an injected clock and an in-test provider.
