# Trust dashboard reconcile - Console side (4 Nov 2026)

Companion to `raucle-cloud/docs/spikes/TRUST-DASHBOARD-reconcile.md`
(the full inventory mapping and the signed-artefact gap live there).
This note records the console-side application of the pinned decision.

## The decision

**The Console embeds/links the H1 operator portal as the Trust add-in's
management UI.** One editor, one version history, one audit trail. The
Trust page in the console narrates and links; deep policy management
happens once, in the portal. No parallel editor exists here and none is
planned - a second editor would fork version history, and a forked
history is not a history.

## What the console shipped

1. **`/api/config` now carries `trust_portal_url`** (env
   `RAUCLE_TRUST_PORTAL_URL`, default `http://127.0.0.1:8090`) - the
   configured portal origin the operator set, the only URL the Trust
   page ever links to. Same never-echoed discipline as the other add-in
   origins.
2. **`GET /api/trust/policies/summary`** - a same-origin proxy for the
   portal's `GET /api/v1/policies/summary` (authenticated counts by
   status chip: active/draft/disabled + total). Same-origin because the
   portal, like every add-in, sends no CORS headers on purpose (the
   wave-2 lesson: every browser read goes through a console proxy).
   Degradation is explicit: the portal offline is a 503 `portal
   offline`; a 401/403 (the alpha console holds no portal credential)
   passes the status through - both render as the same honest pending
   state in the UI. Numbers are never guessed, never faked, never
   locally recomputed.
3. **Trust page: `Manage policies` card** - describes what lives in the
   portal (structured editor, immutable version history with diffs, the
   Trust Ladder, manual activate/disable with signed deployment
   receipts, filtered receipt search) and links to it ("Open the
   portal"). When the summary proxy succeeds, the card shows the
   portal's own inventory chips (green active / amber draft / grey
   disabled counts); when it does not, the card says:
   "Portal owns deep management; summary endpoint pending (portal
   offline)." (or "...no portal credential in alpha."). The card's
   explain line pins the decision in one sentence.

## Why the chips degrade today

The portal's summary endpoint requires a `policies`-granted principal
(fail-closed, like every portal route). A service-to-service read
would need either a portal key minted for the console or an
unauthenticated summary endpoint - the first is an operator decision,
the second weakens the portal. For alpha the honest-pending copy is
the shipped choice; wiring a read-only console credential is a
config task, not a code task, and the UI already renders the chips
when one exists.

## Division of labour (stable contract going forward)

| Concern | Owner |
|---|---|
| Policy authoring, versions, diffs, revert | H1 portal (`/api/v1/policies*`) |
| Activate/disable + signed deployment receipts | H1 portal (`.../activate|disable|deployments`) |
| Receipt search (tool/decision/policy filters) | H1 portal (`/api/v1/receipts`) |
| Product narration, add-in status, counts coherence | Console Trust page |
| Inventory summary chips (read-only, proxied) | Console card <- portal summary |

Anything new in the Trust dashboard scope lands in the portal's API
first; the console gains narration or a proxy for it - never a second
implementation.