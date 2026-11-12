"""Org-IdP OIDC federation for the hosted operator surface (R2 slice 1).

Clean-room implementation of the pattern the raucle gateway ships for its
admin plane (governing spec: ``docs/spec/admin-identity-federation-x3s1.md``
in the raucle repository — the hosted surfaces deliberately MATCH that
idiom so operators configure one shape across the suite):

- OFF by default; enabling is an operator env decision. On enable, discovery
  is fetched at boot: an unreachable, malformed or non-HTTPS issuer refuses
  to start (fail-closed banner instead of a half-open login).
- the client secret NEVER lives in a config document; env value or a 0600
  secret file (env-file pattern), resolved at exchange time.
- login: authorization-code flow with PKCE S256 (RFC 6749 + 7636); the
  ``state`` and ``nonce`` are single-use and live at most five minutes.
- the callback exchanges the code (client_secret_post) and verifies the
  ``id_token``: RS256 against the provider JWKS by ``kid``, strict
  issuer/audience/expiry/nbf/nonce. Any doubt yields a named
  ``OIDC_EXCHANGE_ERROR`` and NO session - never a lenient fallback.
- identity mapping: the verified principal is matched against the hosted
  role registry (env grants + receipted changes). An identity the registry
  does not list is the DEFAULT VIEWER role (fail-closed view-only) - the
  surface has no user records to auto-provision in this slice, and the
  mapping to portal user records is a named follow-up.

Named error prefixes (tests and operators grep these exact strings):
``OIDC_CONFIG_ERROR``, ``OIDC_DISCOVERY_ERROR``, ``OIDC_EXCHANGE_ERROR``.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import stat
import time
from urllib.parse import urlencode

logger = logging.getLogger(__name__)

OIDC_CONFIG_ERROR = "OIDC_CONFIG_ERROR"
OIDC_DISCOVERY_ERROR = "OIDC_DISCOVERY_ERROR"
OIDC_EXCHANGE_ERROR = "OIDC_EXCHANGE_ERROR"

PKCE_CODE_CHALLENGE_METHOD = "S256"
DEFAULT_SCOPE = "openid profile email"
DEFAULT_TIMEOUT_SECONDS = 5.0
SECRETS_MIN_LENGTH = 8


class HostedOIDCError(Exception):
    """A named OIDC failure; the message carries the greppable prefix."""

    def __init__(self, prefix: str, detail: str) -> None:
        super().__init__(f"{prefix}: {detail}")
        self.prefix = prefix


def _config_error(detail: str) -> HostedOIDCError:
    return HostedOIDCError(OIDC_CONFIG_ERROR, detail)


def _discovery_error(detail: str) -> HostedOIDCError:
    return HostedOIDCError(OIDC_DISCOVERY_ERROR, detail)


class HostedOIDCConfig:
    """Operator-facing provider configuration for one hosted surface."""

    def __init__(
        self,
        issuer_url: str,
        client_id: str,
        *,
        redirect_uri: str = "",
        scope: str = DEFAULT_SCOPE,
    ) -> None:
        issuer_url = (issuer_url or "").strip()
        client_id = (client_id or "").strip()
        if not issuer_url:
            raise _config_error("issuer_url is required when OIDC federation is enabled")
        if not issuer_url.startswith("https://"):
            # Identity documents and code exchanges must not travel plaintext.
            raise _config_error(f"issuer_url must be an https:// URL, got {issuer_url!r}")
        if not client_id:
            raise _config_error("client_id is required when OIDC federation is enabled")
        self.issuer_url = issuer_url.rstrip("/")
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.scope = scope or DEFAULT_SCOPE


def client_secret_from_env(env: dict[str, str] | None = None) -> str:
    """Resolve the client secret from env or a 0600 secret FILE.

    Same contract as the gateway's: ``*_CLIENT_SECRET`` env value, or
    ``*_CLIENT_SECRET_FILE`` pointing at a mode-0600 file (a looser file is
    refused fail-closed rather than read). Never a config document. An
    empty result leaves login fail-closed at exchange time.
    """
    env = dict(os.environ if env is None else env)
    file_path = env.get("OAA_HOSTED_OIDC_CLIENT_SECRET_FILE", "").strip()
    if file_path:
        try:
            mode = stat.S_IMODE(os.stat(file_path).st_mode)
            if mode & 0o077:
                raise _config_error(
                    f"OAA_HOSTED_OIDC_CLIENT_SECRET_FILE {file_path!r} must be "
                    f"mode 0600, found {mode:03o}"
                )
            with open(file_path, encoding="utf-8") as fh:
                value = fh.read().strip()
        except OSError as exc:
            raise _config_error(
                f"OAA_HOSTED_OIDC_CLIENT_SECRET_FILE is set but unreadable ({exc})"
            ) from exc
        if not value:
            raise _config_error(f"OAA_HOSTED_OIDC_CLIENT_SECRET_FILE {file_path!r} is empty")
        return value
    return env.get("OAA_HOSTED_OIDC_CLIENT_SECRET", "").strip()


def make_pkce_pair() -> tuple[str, str]:
    """RFC 7636 verifier + its S256 challenge."""
    verifier = base64.urlsafe_b64encode(os.urandom(48)).decode("ascii").rstrip("=")
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
        .decode("ascii")
        .rstrip("=")
    )
    return verifier, challenge


def b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _https_url(value, what: str) -> str:
    if not isinstance(value, str) or not value:
        raise _discovery_error(f"discovery document is missing {what}")
    if not value.startswith("https://"):
        raise _discovery_error(f"{what} must be https:// in the discovery document")
    return value


class HostedOIDCFederation:
    """Discovery, PKCE login, exchange and id_token verification."""

    def __init__(
        self,
        config: HostedOIDCConfig,
        client_secret: str,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        http_get=None,
        http_post_form=None,
        clock=None,
    ) -> None:
        self.config = config
        self._secret = client_secret
        self._timeout = timeout_seconds
        self._http_get = http_get or _default_http_get
        self._http_post_form = http_post_form or _default_http_post_form
        self._clock = clock or time.time
        self.authorization_endpoint = ""
        self.token_endpoint = ""
        self.jwks_uri = ""
        self._jwks_keys: dict[str, tuple] = {}
        self._started = False

    def start(self) -> None:
        """Fetch + validate discovery and JWKS. Fail-closed: any failure
        refuses to start the surface (the composition root refuses with it)."""
        discovery_url = self.config.issuer_url + "/.well-known/openid-configuration"
        try:
            raw = self._http_get(discovery_url, self._timeout)
        except Exception as exc:
            raise _discovery_error(
                f"discovery fetch failed for issuer {self.config.issuer_url!r}: {exc}"
            ) from exc
        try:
            doc = json.loads(raw)
        except ValueError as exc:
            raise _discovery_error(f"discovery document is not JSON: {exc}") from exc
        if not isinstance(doc, dict):
            raise _discovery_error("discovery document is not a JSON object")
        doc_issuer = doc.get("issuer")
        if doc_issuer != self.config.issuer_url:
            # RFC 8414 3.3: the document issuer must match exactly;
            # trailing-slash drift is refused, never silently accepted.
            raise _discovery_error(
                f"discovery issuer {doc_issuer!r} does not match configured "
                f"issuer {self.config.issuer_url!r}"
            )
        self.authorization_endpoint = _https_url(
            doc.get("authorization_endpoint"), "authorization_endpoint"
        )
        self.token_endpoint = _https_url(doc.get("token_endpoint"), "token_endpoint")
        self.jwks_uri = _https_url(doc.get("jwks_uri"), "jwks_uri")
        self._load_jwks()
        self._started = True
        logger.info(
            "hosted OIDC federation started: issuer %s, PKCE S256, RS256-only",
            self.config.issuer_url,
        )

    def _load_jwks(self) -> None:
        try:
            raw = self._http_get(self.jwks_uri or "", self._timeout)
        except Exception as exc:
            raise _discovery_error(f"JWKS fetch failed ({self.jwks_uri!r}): {exc}") from exc
        try:
            jwks = json.loads(raw)
        except ValueError as exc:
            raise _discovery_error(f"JWKS document is not JSON: {exc}") from exc
        keys = jwks.get("keys") if isinstance(jwks, dict) else None
        if not isinstance(keys, list) or not keys:
            raise _discovery_error("JWKS document carries no keys")
        loaded = _jwks_rsa_keys(keys)
        if not loaded:
            raise _discovery_error("JWKS carries no usable RSA signing keys")
        self._jwks_keys = loaded

    def require_started(self) -> None:
        if not self._started:
            raise _discovery_error("federation has not started; discovery must succeed first")
        if not self.authorization_endpoint or not self.token_endpoint:
            raise _discovery_error("discovery left required endpoints unset")

    # ------------------------------------------------------- login + verify
    def authorization_url(self, state: str, nonce: str, code_verifier: str) -> str:
        """The provider authorization URL (PKCE S256 bound)."""
        self.require_started()
        if not self.config.redirect_uri:
            raise _config_error(
                "redirect_uri is required; set OAA_HOSTED_OIDC_REDIRECT_URI_* for this surface"
            )
        challenge = (
            base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
            .decode("ascii")
            .rstrip("=")
        )
        params = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": self.config.scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": PKCE_CODE_CHALLENGE_METHOD,
        }
        sep = "&" if "?" in self.authorization_endpoint else "?"
        return self.authorization_endpoint + sep + urlencode(params)

    def exchange_code(self, code: str, code_verifier: str, expected_nonce: str = "") -> dict:
        """Exchange + verify; returns the verified id_token claims.

        No session is ever minted on doubt: every failure raises a named
        OIDC_EXCHANGE_ERROR (or OIDC_CONFIG_ERROR for a missing secret).
        """
        self.require_started()
        if not code or not isinstance(code, str):
            raise HostedOIDCError(OIDC_EXCHANGE_ERROR, "authorization code is missing")
        if not code_verifier:
            raise HostedOIDCError(OIDC_EXCHANGE_ERROR, "PKCE code_verifier is required")
        if not self._secret:
            raise _config_error(
                "client secret is not configured; set OAA_HOSTED_OIDC_CLIENT_SECRET "
                "or OAA_HOSTED_OIDC_CLIENT_SECRET_FILE"
            )
        if len(self._secret) < SECRETS_MIN_LENGTH:
            raise _config_error("configured client secret is implausibly short")
        if not self.config.redirect_uri:
            raise _config_error("redirect_uri is required to exchange the code")
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.config.redirect_uri,
            "client_id": self.config.client_id,
            "client_secret": self._secret,
            "code_verifier": code_verifier,
        }
        try:
            raw = self._http_post_form(self.token_endpoint, form, self._timeout)
        except Exception as exc:
            raise HostedOIDCError(OIDC_EXCHANGE_ERROR, f"token exchange failed: {exc}") from exc
        try:
            tokens = json.loads(raw)
        except ValueError as exc:
            raise HostedOIDCError(
                OIDC_EXCHANGE_ERROR, f"token response is not JSON: {exc}"
            ) from exc
        id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
        if not id_token or not isinstance(id_token, str):
            raise HostedOIDCError(OIDC_EXCHANGE_ERROR, "token response carries no id_token")
        return self.verify_id_token(id_token, expected_nonce=expected_nonce)

    def verify_id_token(self, id_token: str, *, expected_nonce: str = "") -> dict:
        self.require_started()
        parts = id_token.split(".")
        if len(parts) != 3:
            raise HostedOIDCError(OIDC_EXCHANGE_ERROR, "id_token is not a compact JWS")
        try:
            header = json.loads(b64url_decode(parts[0]))
            claims = json.loads(b64url_decode(parts[1]))
        except (ValueError, TypeError) as exc:
            raise HostedOIDCError(
                OIDC_EXCHANGE_ERROR, f"id_token segments are undecodable: {exc}"
            ) from exc
        if not isinstance(header, dict) or not isinstance(claims, dict):
            raise HostedOIDCError(OIDC_EXCHANGE_ERROR, "id_token header or claims are not objects")
        key = self._signing_key(header)
        _verify_signature(key, parts)
        _check_claims(claims, self._clock, self.config, expected_nonce)
        return claims

    def _signing_key(self, header: dict):
        """The JWKS RSA key that signed this id_token (fail-closed on gaps)."""
        if header.get("alg") != "RS256":
            raise HostedOIDCError(
                OIDC_EXCHANGE_ERROR,
                f"unsupported id_token alg {header.get('alg')!r}; only RS256 is accepted",
            )
        kid = header.get("kid") or ""
        entry = self._jwks_keys.get(kid)
        if entry is None:
            raise HostedOIDCError(
                OIDC_EXCHANGE_ERROR, f"id_token kid {kid!r} is not in the current JWKS"
            )
        return entry[0]


def _check_claims(claims: dict, clock, config: HostedOIDCConfig, expected_nonce: str) -> None:
    issuer = config.issuer_url
    if claims.get("iss") != issuer:
        raise HostedOIDCError(
            OIDC_EXCHANGE_ERROR,
            f"id_token issuer {claims.get('iss')!r} does not match {issuer!r}",
        )
    aud = claims.get("aud")
    aud_list = aud if isinstance(aud, list) else [aud]
    if config.client_id not in [a for a in aud_list if isinstance(a, str)]:
        raise HostedOIDCError(
            OIDC_EXCHANGE_ERROR, "id_token audience does not include this client_id"
        )
    now = clock()
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)) or now >= exp:
        raise HostedOIDCError(OIDC_EXCHANGE_ERROR, "id_token is expired or carries no usable exp")
    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and now < nbf:
        raise HostedOIDCError(OIDC_EXCHANGE_ERROR, "id_token is not yet valid (nbf in the future)")
    if expected_nonce and claims.get("nonce") != expected_nonce:
        raise HostedOIDCError(
            OIDC_EXCHANGE_ERROR, "id_token nonce does not match the login request"
        )
    if not claims.get("sub"):
        raise HostedOIDCError(OIDC_EXCHANGE_ERROR, "id_token carries no sub claim")


def _jwks_rsa_keys(keys: list) -> dict[str, tuple]:
    """The usable RSA signing keys of a JWKS ``keys`` list (kid -> key)."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers  # noqa: PLC0415 - heavy import only on the JWKS path

    loaded: dict[str, tuple] = {}
    for jwk in keys:
        if (
            not isinstance(jwk, dict)
            or jwk.get("kty") != "RSA"
            or jwk.get("use")
            not in (
                None,
                "sig",
            )
        ):
            continue
        kid = jwk.get("kid") or ""
        try:
            numbers = RSAPublicNumbers(
                e=int.from_bytes(b64url_decode(jwk["e"]), "big"),
                n=int.from_bytes(b64url_decode(jwk["n"]), "big"),
            )
            key = numbers.public_key()
        except (KeyError, ValueError, TypeError):
            continue
        loaded[kid] = (key, jwk.get("alg") or "RS256")
    return loaded


def _verify_signature(key, parts: list[str]) -> None:
    """RS256-verify the id_token over its signing input (fail-closed)."""
    try:
        from cryptography.exceptions import InvalidSignature  # noqa: PLC0415 - crypto-only path
        from cryptography.hazmat.primitives import hashes  # noqa: PLC0415 - crypto-only path
        from cryptography.hazmat.primitives.asymmetric import padding  # noqa: PLC0415 - crypto-only path
    except ImportError:  # pragma: no cover - cryptography ships with the suite
        raise HostedOIDCError(
            OIDC_EXCHANGE_ERROR, "cryptography unavailable; cannot verify id_token"
        ) from None
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    try:
        key.verify(b64url_decode(parts[2]), signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise HostedOIDCError(
            OIDC_EXCHANGE_ERROR, "id_token signature verification failed"
        ) from exc


def _default_http_get(url: str, timeout: float) -> bytes:
    from urllib.request import urlopen  # noqa: PLC0415

    with urlopen(url, timeout=timeout) as resp:
        return resp.read()


def _default_http_post_form(url: str, form: dict[str, str], timeout: float) -> bytes:
    from urllib.request import Request, urlopen  # noqa: PLC0415

    data = urlencode(form).encode("ascii")
    req = Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urlopen(req, timeout=timeout) as resp:
        return resp.read()
