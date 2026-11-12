"""FastAPI glue for the hosted operator surface auth (R2 slice 1).

Composition point for the console and the investigation UI: one
:class:`HostedAuth` instance per surface boot

- resolves + validates the env configuration (fail-closed: a partially
  enabled config refuses the app, so no half-open login exists);
- when enabled, runs OIDC discovery at boot and refuses on any doubt
  (the gateway's boot-refusal idiom, never a half-open login);
- binds routes through :meth:`HostedAuth.bind`, which records the route's
  (method, path, capability) into the permission matrix and attaches a
  route-level enforcement dependency in enabled mode;
- installs a fail-closed default-deny net: in enabled mode, any request
  path that is neither a bound route nor an explicitly exempt shell path is
  refused - an unmapped route can never leak;
- registers the shared session/OIDC/role routes, matching the gateway's
  admin-plane idiom (identical path names and response shapes, so
  operators configure and debug one idiom across the suite).

Role enforcement is route-by-route against :mod:`oaa_hosted_auth.rbac`;
role changes are receipted into the hashed ledger and replayed into the
registry, taking effect on the next request.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import logging
import os
import pathlib
import re
import secrets
import time
from typing import Any

import fastapi
from fastapi.responses import HTMLResponse, JSONResponse

from . import config as _config
from . import rbac
from .federation import (
    OIDC_EXCHANGE_ERROR,
    HostedOIDCConfig,
    HostedOIDCError,
    HostedOIDCFederation,
    client_secret_from_env,
    make_pkce_pair,
)
from .ledger import HostedReceiptLedger
from .rbac import PUBLIC, READ, ROLE_RANK, ROLES, SECURITY, SESSION, RoleRegistry
from .sessions import HostedSessionManager, SessionOpenError, principal_ids

logger = logging.getLogger(__name__)

PENDING_TTL_SECONDS = 300
BEARER_PREFIX = "Bearer "
SUBJECT_RE = re.compile(r"[A-Za-z0-9@._:+-]{1,128}")

# Auto-generated API-documentation surfaces: their content is the route
# registry itself (no data) and the alpha already serves them today.
NET_EXEMPT_EXACT = frozenset({"/openapi.json", "/docs", "/redoc"})


class HostedPrincipal:
    """The per-request identity: verified identity strings + effective role."""

    __slots__ = ("claims", "identity_strings", "role", "session_id", "subject")

    def __init__(
        self,
        subject: str,
        role: str,
        identity_strings: list[str],
        session_id: str = "",
        claims: dict | None = None,
    ) -> None:
        self.subject = subject
        self.role = role
        self.identity_strings = identity_strings
        self.session_id = session_id
        self.claims = claims


def _template_regex(path: str) -> re.Pattern[str]:
    """A concrete-path matcher for one route template (braces = one segment)."""
    return re.compile("^" + re.sub(r"\{[^}]+\}", "[^/]+", path) + "$")


class HostedDenial(Exception):
    """Raised by route denials that must render an HTML fail-closed page
    (the no-JS operator surfaces). FastAPI ignores a dependency's returned
    Response, so the page travels as an exception + app-level handler
    instead - the JSON denial paths keep their plain HTTPException shape."""

    def __init__(self, page: str) -> None:
        super().__init__("hosted surface denial")
        self.page = page


class HostedAuth:
    """One surface's auth: config, federation, sessions, roles, routes."""

    def __init__(self, surface: str) -> None:
        self.surface = surface
        self.enabled = False
        self.federation: HostedOIDCFederation | None = None
        self.sessions: HostedSessionManager | None = None
        self.registry = RoleRegistry()
        self.ledger: HostedReceiptLedger | None = None
        self.settings = None
        self._pending: dict[str, dict] = {}
        self._bound: list[dict] = []
        self._templates: list[tuple[re.Pattern[str], str]] = []

    # ------------------------------------------------------------------ boot
    @classmethod
    def boot(
        cls,
        surface: str,
        *,
        default_state_dir: str = "",
        env: dict[str, str] | None = None,
        http_get=None,
        http_post_form=None,
        clock=None,
    ) -> HostedAuth:
        """Build + start the surface auth, fail-closed at operator mistakes.

        Every misconfiguration or discovery failure raises HostedOIDCError;
        the composition root refuses to build the surface entirely (the
        gateway's boot-refusal idiom): enabled-and-broken NEVER ships
        half-open.
        """
        auth = cls(surface)
        env = dict(env if env is not None else os.environ)
        redirect_env = (
            _config.REDIRECT_URI_ENV_CONSOLE
            if surface == "console"
            else _config.REDIRECT_URI_ENV_ASSURANCE
        )
        cfg = _config.from_env_for_surface(
            redirect_env, env=env, default_state_dir=default_state_dir
        )
        auth.settings = cfg
        if not _config.parse_enabled(env):
            return auth
        federation = HostedOIDCFederation(
            HostedOIDCConfig(
                cfg.issuer,
                cfg.client_id,
                redirect_uri=cfg.redirect_uri,
                scope=cfg.scope,
            ),
            client_secret_from_env(env),
            http_get=http_get,
            http_post_form=http_post_form,
            clock=clock,
        )
        # Fail-closed boot: discovery runs HERE; the surface refuses when the
        # issuer is unreachable or malformed, or the JWKS is unusable.
        federation.start()
        clock_kwargs: dict[str, Any] = {}
        if clock is not None:
            # Only the session manager takes the float-epoch clock; the
            # ledger keeps its ISO-timestamp clock (different unit domain,
            # never mixed).
            clock_kwargs["clock"] = clock
        ledger = HostedReceiptLedger(pathlib.Path(cfg.state_dir) / f"hosted-{surface}-ledger.jsonl")
        ledger.load()
        registry = RoleRegistry(rbac.grants_from_env(env))
        for row in ledger.entries("role_change"):
            payload = row.get("payload", {})
            registry.replay_receipt(
                payload.get("action", ""), payload.get("subject", ""), payload.get("role", "")
            )
        sessions = HostedSessionManager(
            ttl_seconds=cfg.session_ttl,
            max_sessions=cfg.sessions_max,
            ledger=ledger,
            **clock_kwargs,
        )
        auth.enabled = True
        auth.federation = federation
        auth.ledger = ledger
        auth.registry = registry
        auth.sessions = sessions
        logger.warning(
            "hosted boot banner: OIDC federation ENABLED for surface %s; provider issuer %s; "
            "sessions + role changes receipted in the hashed ledger; default role view-only",
            surface,
            cfg.issuer,
        )
        return auth

    # ------------------------------------------------------------- binding
    def bind(
        self,
        app: fastapi.FastAPI,
        path: str,
        endpoint,
        *,
        methods: tuple[str, ...] = ("GET",),
        capability: str = READ,
        html_denied: bool = False,
        **route_kwargs: Any,
    ) -> None:
        """Register a route WITH its permission-matrix entry.

        In enabled mode a route-level dependency enforces the capability
        (fail-closed 403s, gateway-shaped); the matrix-walk test asserts
        every data route in the app was bound through this method.
        """
        self._record(capability, path, methods)
        if html_denied:
            self._ensure_denial_handler(app)
        dependencies: list[Any] = []
        if self.enabled and capability != PUBLIC:
            dependencies = [fastapi.Depends(self.require(capability, html_denied=html_denied))]
        app.add_api_route(
            path,
            endpoint,
            methods=list(methods),
            dependencies=dependencies,
            **route_kwargs,
        )

    def _record(self, capability: str, path: str, methods: tuple[str, ...]) -> None:
        for method in methods:
            self._bound.append({"method": method, "path": path, "capability": capability})
            self._templates.append((_template_regex(path), method))

    def bound_routes(self) -> list[dict]:
        """The permission matrix as recorded at registration (test surface)."""
        return [dict(entry) for entry in self._bound]

    # ---------------------------------------------------------- enforcement
    def require(self, capability: str, *, html_denied: bool = False):
        """A FastAPI dependency enforcing *capability* at route level.

        Unauthenticated -> 403 ``auth_required`` (json) or, for no-JS page
        routes, an HTML login-required page (via the HostedDenial handler,
        which the binding attaches to the app lazily). Authenticated but
        insufficient role -> 403 naming the role and the capability,
        exactly the gateway's access-denied shape. Fail-closed both ways.
        """

        def dependency(
            authorization: str | None = fastapi.Header(None),
        ):
            principal = self._authenticate(authorization)
            if principal is None:
                if html_denied:
                    raise HostedDenial(_login_required_page())
                raise fastapi.HTTPException(
                    403,
                    detail={"error": "authentication required", "auth_required": True},
                )
            if not rbac.role_allows(principal.role, capability):
                if html_denied:
                    raise HostedDenial(
                        "<p>your role '"
                        + str(principal.role)
                        + "' is not permitted this page (fail-closed view-only).</p>"
                        "<p><a href='/api/oidc/login'>Log in</a>.</p>"
                    )
                raise fastapi.HTTPException(
                    403,
                    detail={"error": f"Role '{principal.role}' cannot access '{capability}'"},
                )
            return principal

        return dependency

    def _ensure_denial_handler(self, app: fastapi.FastAPI) -> None:
        """Attach the HostedDenial -> HTML-403 handler once per app."""
        if getattr(app.state, "hosted_denial_handler_attached", False):
            return
        app.state.hosted_denial_handler_attached = True

        def _render(request, exc: HostedDenial):
            return HTMLResponse(exc.page, status_code=403)

        app.add_exception_handler(HostedDenial, _render)

    # -------------------------------------------------------- authentication
    def _authenticate(self, authorization: str | None) -> HostedPrincipal | None:
        """Resolve a bearer header to a principal, or None (fail-closed).

        An unknown, expired or malformed token is exactly like a missing
        header: no session, no role, no access. The effective role is
        resolved against the CURRENT registry, so a receipted role change
        takes effect on the next request.
        """
        if self.sessions is None or not isinstance(authorization, str) or not authorization:
            return None
        token = authorization
        if token.startswith(BEARER_PREFIX):
            token = token[len(BEARER_PREFIX) :]
        record = self.sessions.resolve_token(token)
        if record is None:
            return None
        ids = [i for i in (record.get("ids") or []) if i]
        subject = ids[0] if ids else ""
        role = self.registry.effective_for(ids)
        return HostedPrincipal(subject, role, ids, session_id=record.get("session_id", ""))

    # ------------------------------------------------------------ the net
    def install_net(
        self,
        app: fastapi.FastAPI,
        *,
        exempt_exact: tuple[str, ...] = (),
        exempt_prefixes: tuple[str, ...] = (),
    ) -> None:
        """The default-deny net for enabled mode (installed by create_app).

        Any request path the app never bound - and that is not an operator
        shell exemption - is refused, fail-closed, for every caller. The
        per-route capability dependencies still do the real role work; this
        net only guarantees that no unbound path can ever answer.
        """
        if not self.enabled:
            return
        auth = self
        allowed_exact = NET_EXEMPT_EXACT | set(exempt_exact)
        allowed_prefixes = tuple(exempt_prefixes)

        @app.middleware("http")
        async def fail_closed_net(request: fastapi.Request, call_next):
            path = request.scope.get("path", "")
            if path in allowed_exact or path.startswith(allowed_prefixes):
                return await call_next(request)
            for pattern, method in auth._templates:
                if pattern.match(path) and (
                    request.method == method or (method == "GET" and request.method == "HEAD")
                ):
                    return await call_next(request)
            return JSONResponse(
                {"error": "request path is not in the hosted permission matrix"},
                status_code=403,
            )

    # ---------------------------------------------------------------- routes
    def register_shared_routes(self, app: fastapi.FastAPI) -> None:
        """The session/OIDC/role routes, shared by both surfaces.

        Path names and response shapes match the gateway admin plane. A
        disabled surface exposes ONLY the config probe (the SPAs use it to
        decide whether to start a login) and no session routes: in the
        legacy open mode there is nothing to keep.
        """
        self.bind(app, "/api/session/config", self._config_payload, capability=PUBLIC)
        if not self.enabled:
            return

        federation = self.federation
        sessions = self.sessions
        # Single-use pending logins: state -> {nonce, verifier, created_at};
        # bounded, at most PENDING_TTL_SECONDS live (gateway idiom).
        require_session = self.require(SESSION)

        self._record(PUBLIC, "/api/oidc/login", ("GET",))
        self._record(PUBLIC, "/api/oidc/callback", ("POST",))
        self._record(SESSION, "/api/session/logout", ("POST",))
        self._record(SESSION, "/api/session/refresh", ("POST",))
        self._record(SESSION, "/api/session/me", ("GET",))
        self._record(READ, "/api/roles", ("GET",))
        self._record(SECURITY, "/api/roles/{subject}", ("POST",))

        def oidc_login() -> dict:
            now = time.time()
            for stale in [
                s
                for s, rec in self._pending.items()
                if rec["created_at"] + PENDING_TTL_SECONDS < now
            ]:
                self._pending.pop(stale, None)
            state = "oidc_" + hashlib.sha256(secrets.token_bytes(32)).hexdigest()[:32]
            nonce = "n_" + secrets.token_hex(16)
            verifier, _challenge = make_pkce_pair()
            self._pending[state] = {
                "nonce": nonce,
                "code_verifier": verifier,
                "created_at": now,
            }
            url = federation.authorization_url(state, nonce, verifier)
            return {"authorization_url": url, "state": state}

        def oidc_callback(body: dict) -> JSONResponse:
            try:
                claims = self._exchange(body)
            except HostedOIDCError as exc:
                raise fastapi.HTTPException(401, detail={"error": str(exc)}) from exc
            except SessionOpenError as exc:
                raise fastapi.HTTPException(exc.status, detail={"error": exc.reason}) from exc
            principal = self.principal_from_claims(claims)
            opened = sessions.open(principal)
            return JSONResponse(
                {
                    "session_token": opened["token"],
                    "expires_at": opened["expires_at"],
                    "subject": principal.subject,
                    "role": principal.role,
                    "auth_method": "oidc",
                }
            )

        def session_logout(
            authorization: str | None = fastapi.Header(None),
            # FastAPI dependency injection against a per-boot closure:
            principal: HostedPrincipal = (
                fastapi.Depends(require_session)  # noqa: B008 - FastAPI idiom
            ),
        ) -> dict:
            if not sessions.close(self._token_from(authorization)):
                raise fastapi.HTTPException(403, detail={"error": "Invalid or expired session"})
            return {"status": "closed", "session_id": principal.session_id}

        def session_refresh(
            authorization: str | None = fastapi.Header(None),
            # FastAPI dependency injection against a per-boot closure:
            principal: HostedPrincipal = (
                fastapi.Depends(require_session)  # noqa: B008 - FastAPI idiom
            ),
        ) -> dict:
            expires_at = sessions.refresh(self._token_from(authorization))
            if expires_at is None:
                raise fastapi.HTTPException(
                    403,
                    detail={"error": "Invalid or expired session", "auth_required": True},
                )
            return {"expires_at": expires_at, "subject": principal.subject, "role": principal.role}

        def session_me(
            # FastAPI dependency injection against a per-boot closure:
            principal: HostedPrincipal = (
                fastapi.Depends(require_session)  # noqa: B008 - FastAPI idiom
            ),
        ) -> dict:
            return {
                "subject": principal.subject,
                "role": principal.role,
                "session_id": principal.session_id,
            }

        def roles_list() -> dict:
            return {
                "roles": list(ROLES),
                "default_role": rbac.DEFAULT_ROLE,
                "runtime_grants": {
                    subject: sorted(roles, key=lambda r: ROLE_RANK[r])
                    for subject, roles in self.registry.runtime_grants().items()
                },
                "note": "env grant lists apply at boot; env values are never echoed here",
            }

        def role_change(
            subject: str,
            body: dict,
            # FastAPI dependency injection against a per-boot closure:
            principal: HostedPrincipal = (
                fastapi.Depends(require_session)  # noqa: B008 - FastAPI idiom
            ),
        ) -> JSONResponse:
            return self._role_change(subject, body, actor_session=principal.session_id)

        app.add_api_route("/api/oidc/login", oidc_login, methods=["GET"])
        app.add_api_route("/api/oidc/callback", oidc_callback, methods=["POST"])
        app.add_api_route("/api/session/logout", session_logout, methods=["POST"])
        app.add_api_route("/api/session/refresh", session_refresh, methods=["POST"])
        app.add_api_route("/api/session/me", session_me, methods=["GET"])
        app.add_api_route(
            "/api/roles",
            roles_list,
            methods=["GET"],
            dependencies=[fastapi.Depends(self.require(READ))],
        )
        app.add_api_route(
            "/api/roles/{subject}",
            role_change,
            methods=["POST"],
            dependencies=[fastapi.Depends(self.require(SECURITY))],
        )

    # ------------------------------------------------------------ internals
    def _config_payload(self) -> dict:
        if not self.enabled:
            return {"oidc_enabled": False, "surface": self.surface}
        return {
            "oidc_enabled": True,
            "provider_issuer": self.federation.config.issuer_url,
            "session_ttl_seconds": self.sessions.ttl_seconds,
            "surface": self.surface,
        }

    def _token_from(self, authorization: str | None) -> str:
        token = authorization or ""
        if token.startswith(BEARER_PREFIX):
            token = token[len(BEARER_PREFIX) :]
        return token

    def _exchange(self, body: dict) -> dict:
        """Code + verifier exchange over a single-use pending state."""
        if not isinstance(body, dict):
            raise HostedOIDCError(OIDC_EXCHANGE_ERROR, "callback body must be a JSON object")
        if body.get("error"):
            raise HostedOIDCError(
                OIDC_EXCHANGE_ERROR, f"provider refused the login: {body.get('error')}"
            )
        state = body.get("state") or ""
        pending = self._pending.pop(state if isinstance(state, str) else "", None)
        if pending is None or pending["created_at"] + PENDING_TTL_SECONDS < time.time():
            raise HostedOIDCError(
                OIDC_EXCHANGE_ERROR, "unknown or replayed state; restart the login"
            )
        code = body.get("code") or ""
        return self.federation.exchange_code(
            code, pending["code_verifier"], expected_nonce=pending["nonce"]
        )

    def principal_from_claims(self, claims: dict) -> HostedPrincipal:
        """Map VERIFIED id_token claims onto the fail-closed role registry."""
        ids = principal_ids(claims)
        role = self.registry.effective_for(ids)
        return HostedPrincipal(
            subject=ids[0] if ids else "", role=role, identity_strings=ids, claims=claims
        )

    def _role_change(self, sub: str, body: dict, *, actor_session: str = "") -> JSONResponse:
        """Receipted grant/revoke; a change without its receipt takes no
        effect (the ledger is the change's only durable record)."""
        action = body.get("action") if isinstance(body, dict) else None
        role = body.get("role") if isinstance(body, dict) else None
        reason = body.get("reason") if isinstance(body, dict) else ""
        if action not in ("grant", "revoke"):
            return JSONResponse({"error": "action must be 'grant' or 'revoke'"}, status_code=422)
        if role not in ROLE_RANK:
            return JSONResponse(
                {"error": "role must be one of " + ", ".join(ROLES)}, status_code=422
            )
        if not isinstance(reason, str) or not reason.strip():
            return JSONResponse({"error": "reason is required for a role change"}, status_code=422)
        if not SUBJECT_RE.match(sub):
            return JSONResponse({"error": "malformed subject"}, status_code=422)
        try:
            row = self.ledger.append(
                "role_change",
                {
                    "action": action,
                    "subject": sub,
                    "role": role,
                    "reason": reason.strip(),
                    "actor": actor_session,
                },
            )
        except Exception:
            logger.exception("role-change receipt emission failed")
            return JSONResponse(
                {"error": "role ledger unavailable; change refused"}, status_code=503
            )
        self.registry.replay_receipt(action, sub, role)
        return JSONResponse(
            {
                "subject": sub,
                "role": role,
                "action": action,
                "receipt_hash": row.get("hash"),
                "effective_role": self.registry.effective_for([sub]),
            }
        )


def _login_required_page() -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<title>login required</title></head><body>"
        "<p>This page requires an authenticated operator session.</p>"
        "<p><a href='/api/oidc/login'>Log in with your organisation's identity"
        " provider</a>, then reload this page.</p>"
        "</body></html>"
    )
