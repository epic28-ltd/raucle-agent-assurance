"""Hosted-surface role ladder (R2 slice 1): viewer / operator / security-admin.

The hosted operator surfaces (console + investigation UI) previously had a
single implicit operator model: every HTTP caller was every role. This module
gives the surface a three-role ladder and a permission matrix enforced at
route level:

- ``viewer``        - read everything the surface shows, run nothing;
- ``operator``      - viewer plus the surface's mutating actions
  (red runs, findings intake, triage board moves, fleet ingest/reset);
- ``security-admin`` - operator plus the security plane: granting and
  revoking principal roles via the receipted role-change endpoint
  (``POST /api/roles/{subject}``).

Fail-closed defaults, stated as code:

- an identity the registry knows nothing about is a ``viewer`` (view-only);
  no unlisted principal ever inherits write or security authority;
- a role string that the ladder does not define downgrades to ``viewer``
  - an unknown role can never mean "more privileges";
- a principal granted several roles gets the most restrictive one
  (rank-min), so a contradictory configuration cannot silently elevate;
- every route must carry an entry in the surface's route-capability map:
  a route without a mapped capability fails the matrix-completeness test
  in CI rather than shipping with silent open access.

Role grants come from two sources, replayed in a fixed order each boot:
the operator's env lists (``OAA_HOSTED_ROLE_*``), then the surface's own
receipted role-change ledger (grant adds, revoke removes). A runtime change
is therefore a lifecycle event with a receipt record in the hashed chain -
never a silent lookup swap - mirroring the gateway admin-plane idiom
(docs/spec/admin-identity-federation-x3s1.md in the raucle repository is
the governing pattern for the OIDC + session machinery this module serves).
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os

# The role ladder, lowest first. Rank order IS authority order.
ROLES: tuple[str, ...] = ("viewer", "operator", "security-admin")
ROLE_RANK: dict[str, int] = {role: rank for rank, role in enumerate(ROLES)}

# Anything unlisted or unknown resolves to view-only; never to more.
DEFAULT_ROLE = "viewer"

# Capability vocabulary for the permission matrix. A route carries exactly
# one minimum capability:
READ = "read"  # every authenticated principal (viewer and up)
WRITE = "write"  # mutating surface actions (operator and up)
SECURITY = "security"  # the security plane: role grants/revocations
SESSION = "session"  # the caller's own session lifecycle (any principal)
PUBLIC = "public"  # anonymous: login routes, health, static shell

CAPABILITY_MINIMUM = {
    READ: DEFAULT_ROLE,
    WRITE: "operator",
    SECURITY: "security-admin",
    SESSION: DEFAULT_ROLE,  # any authenticated principal runs its own session
}


def role_allows(role: str, capability: str) -> bool:
    """True when *role* meets the minimum rank for *capability*.

    Fail-closed: an unknown role string (including empty and None-shaped
    values) is treated as the default view-only role, so a misconfigured
    claim can only ever be less powerful, never more.
    """
    effective = ROLE_RANK.get(role, ROLE_RANK[DEFAULT_ROLE])
    minimum = CAPABILITY_MINIMUM.get(capability)
    if minimum is None:
        # Unknown capability names deny (fail-closed) without inventing
        # authority for them.
        return False
    return effective >= ROLE_RANK[minimum]


def effective_role(granted: list[str] | tuple[str, ...] | None) -> str:
    """Rank-min of the granted roles; unknown members degrade to viewer."""
    ranks = [ROLE_RANK[r] for r in (granted or []) if r in ROLE_RANK]
    if not ranks:
        return DEFAULT_ROLE
    return ROLES[min(ranks)]


# Env grant lists: comma-separated identities (subject id, email,
# preferred_username or name claim) per role. The env key cannot carry the
# dash, so the security-admin key is SECURITY_ADMIN.
ROLE_ENV_KEYS: dict[str, str] = {
    "viewer": "OAA_HOSTED_ROLE_VIEWER",
    "operator": "OAA_HOSTED_ROLE_OPERATOR",
    "security-admin": "OAA_HOSTED_ROLE_SECURITY_ADMIN",
}


def grants_from_env(env: dict[str, str] | None = None) -> dict[str, set[str]]:
    """{role: identity-set} from the ``OAA_HOSTED_ROLE_*`` env lists."""
    env = dict(os.environ if env is None else env)
    grants: dict[str, set[str]] = {}
    for role, key in ROLE_ENV_KEYS.items():
        raw = env.get(key, "")
        identities = {part.strip() for part in raw.split(",") if part.strip()}
        if identities:
            grants[role] = identities
    return grants


class RoleRegistry:
    """Who holds which hosted-surface role, replayed receipt by receipt.

    Boot order: env grants first (operator deploy-time authority), then the
    surface's own receipted role-change events in ledger order (grant adds,
    revoke removes; the most recent receipt for a pair is the truth). This
    makes a role change a lifecycle event with a receipt - never a silent
    lookup swap - while the env re-asserts the deploy-time baseline on every
    boot (an operator tightening an env list reverts runtime drift).
    """

    def __init__(
        self,
        env_grants: dict[str, set[str]] | None = None,
        *,
        default_role: str = DEFAULT_ROLE,
    ) -> None:
        self._env_grants = {role: set(ids) for role, ids in (env_grants or {}).items()}
        self._runtime: dict[str, set[str]] = {}
        self.default_role = default_role

    def replay_receipt(self, action: str, subject: str, role: str) -> None:
        """Apply one receipted role change to the runtime layer."""
        if role not in ROLE_RANK or not subject:
            return  # unknown roles/empty subjects invent no authority on replay
        if action == "grant":
            self._runtime.setdefault(subject, set()).add(role)
        elif action == "revoke":
            self._runtime.get(subject, set()).discard(role)
        # Unknown actions are ignored on replay: a corrupted or
        # future-versioned ledger line must not invent authority.

    def roles_for(self, identity_strings: list[str]) -> list[str]:
        """Every role granted to a principal carrying any identity string.

        The identity strings of one principal are its verified token
        claims: the ``sub`` plus the friendly claims an operator can name
        in a grant list before the first login (email,
        preferred_username, name). Nothing unlisted falls through: the
        caller resolves an empty list to the default view-only role.
        """
        wanted = {s for s in identity_strings if s}
        roles: set[str] = set()
        for role, identities in self._env_grants.items():
            if wanted & identities:
                roles.add(role)
        for subject, granted in self._runtime.items():
            if subject in wanted:
                roles |= granted
        return sorted(roles, key=lambda r: ROLE_RANK[r])

    def runtime_grants(self) -> dict[str, set[str]]:
        """The receipted runtime layer only (the /api/roles view; env lists
        are deployment configuration and are never echoed in responses)."""
        return {subject: set(roles) for subject, roles in self._runtime.items()}

    def effective_for(self, identity_strings: list[str]) -> str:
        """The fail-closed effective role for a principal (rank-min)."""
        return effective_role(self.roles_for(identity_strings))
