"""Env configuration for the hosted operator surface (R2 slice 1).

One resolution point for both surfaces (console + investigation UI), wired
to the env names the suite documents. Everything OFF by default; every
activation failure is a NAMED ``OIDC_CONFIG_ERROR`` so an operator who
enables the feature half-configured refuses at boot, never half-open.

| Setting | Env | Notes |
| --- | --- | --- |
| enabled | ``OAA_HOSTED_OIDC_ENABLED`` | 1/true/yes; default OFF |
| issuer | ``OAA_HOSTED_OIDC_ISSUER`` | must be https:// |
| client id | ``OAA_HOSTED_OIDC_CLIENT_ID`` | required when enabled |
| console callback | ``OAA_HOSTED_OIDC_REDIRECT_URI_CONSOLE`` | console surface |
| assurance callback | ``OAA_HOSTED_OIDC_REDIRECT_URI_ASSURANCE`` | investigation surface |
| scope | ``OAA_HOSTED_OIDC_SCOPE`` | default ``openid profile email`` |
| secret | ``OAA_HOSTED_OIDC_CLIENT_SECRET`` | env only, never a config file |
| secret file | ``OAA_HOSTED_OIDC_CLIENT_SECRET_FILE`` | path to a 0600 file |
| session ttl | ``OAA_HOSTED_SESSION_TTL`` | seconds, >= 60, default 3600 |
| session cap | ``OAA_HOSTED_SESSIONS_MAX`` | default 64 |
| state dir | ``OAA_HOSTED_STATE_DIR`` | where the receipted ledger lives |
| role lists | ``OAA_HOSTED_ROLE_*`` per role | comma-separated identity lists |

Fail-closed notes:

- the secret never comes from a config file, only env or a secret file
  (which must be mode 0600; anything looser refuses rather than read);
- one of secret env/file is REQUIRED when enabled: a login that cannot
  exchange is a misconfiguration, not a runtime surprise;
- the redirect URI for a surface is REQUIRED when that surface enables
  federation: an IdP redirect to nowhere is refused at boot.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import os

from .federation import OIDC_CONFIG_ERROR, HostedOIDCError

TRUTHY = ("1", "true", "yes")

REDIRECT_URI_ENV_CONSOLE = "OAA_HOSTED_OIDC_REDIRECT_URI_CONSOLE"
REDIRECT_URI_ENV_ASSURANCE = "OAA_HOSTED_OIDC_REDIRECT_URI_ASSURANCE"
STATE_DIR_ENV = "OAA_HOSTED_STATE_DIR"


def _enabled(env: dict[str, str]) -> bool:
    return env.get("OAA_HOSTED_OIDC_ENABLED", "").strip().lower() in TRUTHY


def _int_value(env: dict[str, str], key: str, default: int) -> int:
    raw = env.get(key, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise HostedOIDCError(OIDC_CONFIG_ERROR, f"{key} must be an integer, got {raw!r}") from None


def parse_enabled(env: dict[str, str] | None = None) -> bool:
    """Whether the env ACTIVATES the hosted OIDC feature (validates the flag).

    ``1``/``true``/``yes`` enable; ``0``/``false``/``no``/absent disable;
    anything else is a configuration error, never a silent guess.
    """
    env = dict(os.environ if env is None else env)
    flag = env.get("OAA_HOSTED_OIDC_ENABLED", "").strip().lower()
    if flag and flag not in TRUTHY and flag not in ("0", "false", "no"):
        raise HostedOIDCError(
            OIDC_CONFIG_ERROR,
            "OAA_HOSTED_OIDC_ENABLED must be 1/true/yes (enable) or 0/false/no "
            "(disable); omit to disable",
        )
    return _enabled(env)


class SurfaceAuthConfig:
    """Resolved, validated auth configuration for ONE hosted surface.

    The surface-specific redirect URI arrives from the composition root
    (console vs assurance); the rest is shared with the other surface.
    """

    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        session_ttl: int,
        sessions_max: int,
        state_dir: str,
    ) -> None:
        self.issuer = issuer
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.session_ttl = session_ttl
        self.sessions_max = sessions_max
        self.state_dir = state_dir


def from_env_for_surface(
    redirect_env_name: str,
    *,
    env: dict[str, str] | None = None,
    default_state_dir: str = "",
) -> SurfaceAuthConfig:
    """Resolve + validate the shared settings for one surface.

    *redirect_env_name* is the surface's own callback env key; an enabled
    surface refuses at boot when it is unset or empty. *default_state_dir*
    is the per-service ledger home when ``OAA_HOSTED_STATE_DIR`` is unset.
    """
    env = dict(os.environ if env is None else env)
    if not parse_enabled(env):
        # Disabled: nothing to validate - the defaults stay untouched.
        return SurfaceAuthConfig(
            issuer="",
            client_id="",
            redirect_uri="",
            scope="",
            session_ttl=3600,
            sessions_max=64,
            state_dir=default_state_dir,
        )
    issuer = env.get("OAA_HOSTED_OIDC_ISSUER", "").strip()
    if not issuer:
        raise HostedOIDCError(
            OIDC_CONFIG_ERROR,
            "OAA_HOSTED_OIDC_ISSUER is required when the feature is enabled",
        )
    if not issuer.startswith("https://"):
        raise HostedOIDCError(
            OIDC_CONFIG_ERROR, f"OAA_HOSTED_OIDC_ISSUER must be an https:// URL, got {issuer!r}"
        )
    client_id = env.get("OAA_HOSTED_OIDC_CLIENT_ID", "").strip()
    if not client_id:
        raise HostedOIDCError(
            OIDC_CONFIG_ERROR,
            "OAA_HOSTED_OIDC_CLIENT_ID is required when the feature is enabled",
        )
    redirect_uri = env.get(redirect_env_name, "").strip()
    if not redirect_uri:
        raise HostedOIDCError(
            OIDC_CONFIG_ERROR, f"{redirect_env_name} is required when the feature is enabled"
        )
    secret_set = bool(
        env.get("OAA_HOSTED_OIDC_CLIENT_SECRET", "").strip()
        or env.get("OAA_HOSTED_OIDC_CLIENT_SECRET_FILE", "").strip()
    )
    if not secret_set:
        raise HostedOIDCError(
            OIDC_CONFIG_ERROR,
            "set OAA_HOSTED_OIDC_CLIENT_SECRET or OAA_HOSTED_OIDC_CLIENT_SECRET_FILE; "
            "the login exchanges never work without one",
        )
    ttl = _int_value(env, "OAA_HOSTED_SESSION_TTL", 3600)
    if ttl < 60:
        raise HostedOIDCError(
            OIDC_CONFIG_ERROR, "OAA_HOSTED_SESSION_TTL must be at least 60 seconds"
        )
    sessions_max = _int_value(env, "OAA_HOSTED_SESSIONS_MAX", 64)
    if sessions_max <= 0:
        raise HostedOIDCError(OIDC_CONFIG_ERROR, "OAA_HOSTED_SESSIONS_MAX must be positive")
    from .federation import DEFAULT_SCOPE  # noqa: PLC0415 - cheap, avoids load order

    return SurfaceAuthConfig(
        issuer=issuer,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=env.get("OAA_HOSTED_OIDC_SCOPE", "").strip() or DEFAULT_SCOPE,
        session_ttl=ttl,
        sessions_max=sessions_max,
        state_dir=env.get(STATE_DIR_ENV, "").strip() or default_state_dir,
    )
