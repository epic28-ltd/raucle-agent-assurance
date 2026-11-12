"""Hosted-surface auth for the Raucle operator surfaces (R2 slice 1).

Shared by the console (:mod:`raucle_console`) and the investigation UI
(:mod:`oaa_investigation_ui`): org-IdP OIDC federation, receipted sessions,
the viewer/operator/security-admin role ladder with a route-level
permission matrix, and the hashed receipt ledger for session + role
lifecycle events. The gateway's admin-plane OIDC/session idiom (raucle X3
slice 1) is the governing pattern; see docs/architecture/
hosted-surface-oidc-rbac-r2s1.md in this repository.
"""
# SPDX-License-Identifier: Apache-2.0

import pathlib

from .config import parse_enabled
from .federation import (
    DEFAULT_SCOPE,
    OIDC_CONFIG_ERROR,
    OIDC_DISCOVERY_ERROR,
    OIDC_EXCHANGE_ERROR,
    HostedOIDCConfig,
    HostedOIDCError,
    HostedOIDCFederation,
    client_secret_from_env,
    make_pkce_pair,
)
from .hosted import HostedAuth, HostedPrincipal
from .ledger import HostedReceiptLedger, LedgerCorruptError
from .rbac import (
    PUBLIC,
    READ,
    ROLE_RANK,
    ROLES,
    SECURITY,
    SESSION,
    WRITE,
    RoleRegistry,
    effective_role,
    grants_from_env,
    role_allows,
)
from .sessions import (
    DEFAULT_MAX_SESSIONS,
    DEFAULT_SESSION_TTL_SECONDS,
    SESSION_TOKEN_PREFIX,
    HostedSessionManager,
    SessionOpenError,
    hash_session_token,
)

# The hosted-login SPA hook, ONE physical copy under assets/ and served by
# EVERY carrier surface at /static/hosted-auth-hook.js (see
# assets/hosted_auth_hook.js for the contract: it must interpose window.fetch
# before the pages' own scripts run their first fetch).
HOSTED_AUTH_HOOK_JS = pathlib.Path(__file__).resolve().parent / "assets" / "hosted_auth_hook.js"
if not HOSTED_AUTH_HOOK_JS.is_file():  # pragma: no cover - packaging drift guard
    raise RuntimeError(f"missing bundled asset: {HOSTED_AUTH_HOOK_JS}")

__all__ = [
    "DEFAULT_MAX_SESSIONS",
    "DEFAULT_SCOPE",
    "DEFAULT_SESSION_TTL_SECONDS",
    "HOSTED_AUTH_HOOK_JS",
    "OIDC_CONFIG_ERROR",
    "OIDC_DISCOVERY_ERROR",
    "OIDC_EXCHANGE_ERROR",
    "PUBLIC",
    "READ",
    "ROLES",
    "ROLE_RANK",
    "SECURITY",
    "SESSION",
    "SESSION_TOKEN_PREFIX",
    "WRITE",
    "HostedAuth",
    "HostedOIDCConfig",
    "HostedOIDCError",
    "HostedOIDCFederation",
    "HostedPrincipal",
    "HostedReceiptLedger",
    "HostedSessionManager",
    "LedgerCorruptError",
    "RoleRegistry",
    "SessionOpenError",
    "client_secret_from_env",
    "effective_role",
    "grants_from_env",
    "hash_session_token",
    "make_pkce_pair",
    "parse_enabled",
    "role_allows",
]
