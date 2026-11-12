# SPDX-License-Identifier: Apache-2.0
"""R2 slice 1 hosted-surface auth: sessions, OIDC federation, config contract.

Covers the hosted operator surfaces' auth machinery (oaa_hosted_auth):

- session issuance/refresh/expiry and the fail-closed token contract
  (digest-only store, bounded table, receipted lifecycle in the ledger);
- the org-IdP OIDC login end to end against an in-test provider stub
  (discovery, PKCE, exchange, id_token verification, mapping) with every
  named failure shape refusing to mint a session;
- config validation (fail-closed boot) and the ledger's tamper evidence.

The raucle gateway's admin-plane idiom (X3 slice 1,
docs/spec/admin-identity-federation-x3s1.md) is the reference shape: same
route names, same named error prefixes, same fail-closed posture.
"""

from __future__ import annotations

import base64
import json
import pathlib
import sys
import time

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
for _p in (REPO_ROOT / "services" / "investigation-ui" / "src",):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import pytest  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import padding, rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from oaa_hosted_auth import (  # noqa: E402
    OIDC_CONFIG_ERROR,
    OIDC_DISCOVERY_ERROR,
    OIDC_EXCHANGE_ERROR,
    HostedAuth,
    HostedOIDCError,
    HostedReceiptLedger,
    LedgerCorruptError,
    RoleRegistry,
    effective_role,
    role_allows,
)
from oaa_hosted_auth.sessions import (  # noqa: E402
    SESSION_TOKEN_PREFIX,
    SessionOpenError,
)

ISSUER = "https://idp.example.org"
CLIENT_SECRET = "hosted-client-secret-01"
AUDIENCE = "hosted-console"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


class FakeIdP:
    """A minimal in-test OIDC provider: discovery, JWKS, token endpoint."""

    def __init__(self, *, issuer: str = ISSUER, kid: str = "k1") -> None:
        self.issuer = issuer
        self.kid = kid
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.wrong_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.token_error: Exception | None = None
        self.token_payload_override: dict | None = None
        self.claims: dict = {}
        # Fail the discovery/JWKS stage on demand (fail-closed boot tests).
        self.discovery_doc: dict | None = None
        self.jwks_doc: dict | None = None
        self.get_error: Exception | None = None

    def discovery(self) -> dict:
        if self.discovery_doc is not None:
            return self.discovery_doc
        return {
            "issuer": self.issuer,
            "authorization_endpoint": "https://idp.example.org/authorize",
            "token_endpoint": "https://idp.example.org/token",
            "jwks_uri": "https://idp.example.org/jwks.json",
        }

    def jwks(self) -> dict:
        if self.jwks_doc is not None:
            return self.jwks_doc
        numbers = self.key.public_key().public_numbers()
        return {
            "keys": [
                {
                    "kty": "RSA",
                    "kid": self.kid,
                    "use": "sig",
                    "alg": "RS256",
                    "n": b64url(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
                    "e": b64url(numbers.e.to_bytes(3, "big")),
                }
            ]
        }

    def set_claims(
        self,
        sub: str = "sub-console-op",
        *,
        email: str | None = None,
        preferred_username: str | None = None,
        name: str | None = None,
        alg: str = "RS256",
        kid: str | None = None,
        aud: str | None = AUDIENCE,
        iss: str | None = None,
        lifetime: float = 300.0,
        nonce: str | None = None,
        **extra,
    ) -> dict:
        now = time.time()
        claims: dict = {
            "iss": iss if iss is not None else self.issuer,
            "aud": aud if aud is not None else AUDIENCE,
            "sub": sub,
            "exp": now + lifetime,
            "iat": now,
        }
        if nonce:
            claims["nonce"] = nonce
        if email:
            claims["email"] = email
        if preferred_username:
            claims["preferred_username"] = preferred_username
        if name:
            claims["name"] = name
        claims.update(extra)
        self.claims = claims
        self._mint_alg = alg
        self._mint_kid = kid if kid is not None else self.kid
        return claims

    def mint(self, claims: dict | None = None, *, key=None, alg: str = "RS256") -> str:
        """Mint an id_token (defaults to the last set_claims shape)."""
        claims = claims if claims is not None else self.claims
        if not claims:
            raise AssertionError("call set_claims before minting")
        key = key or self.key
        header = {"alg": alg, "kid": self.kid}
        signing_input = (
            b64url(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64url(json.dumps(claims, separators=(",", ":")).encode())
        ).encode("ascii")
        if alg == "RS256":
            signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            signature = b"not-a-real-signature"
        return signing_input.decode("ascii") + "." + b64url(signature)

    def transport(self):
        """(http_get, http_post_form) wired to this provider."""

        def http_get(url: str, timeout: float) -> bytes:
            if self.get_error is not None:
                raise self.get_error
            if url.endswith("/.well-known/openid-configuration"):
                return json.dumps(self.discovery()).encode()
            if url.endswith("/jwks.json"):
                return json.dumps(self.jwks()).encode()
            raise AssertionError(f"unexpected GET in test transport: {url}")

        def http_post_form(url: str, form: dict, timeout: float) -> bytes:
            if self.token_error is not None:
                raise self.token_error
            payload = dict(self.token_payload_override or {})
            payload.setdefault("id_token", self.mint())
            payload.setdefault("token_type", "Bearer")
            return json.dumps(payload).encode()

        return http_get, http_post_form


def enabled_env(
    tmp_path: pathlib.Path,
    *,
    surface: str = "console",
    overrides: dict | None = None,
) -> dict:
    env = {
        "OAA_HOSTED_OIDC_ENABLED": "1",
        "OAA_HOSTED_OIDC_ISSUER": ISSUER,
        "OAA_HOSTED_OIDC_CLIENT_ID": f"hosted-{surface}",
        "OAA_HOSTED_OIDC_REDIRECT_URI_CONSOLE": "http://127.0.0.1:3412/",
        "OAA_HOSTED_OIDC_REDIRECT_URI_ASSURANCE": "http://127.0.0.1:3411/",
        "OAA_HOSTED_OIDC_CLIENT_SECRET": CLIENT_SECRET,
        "OAA_HOSTED_STATE_DIR": str(tmp_path / "hosted-state"),
    }
    env.update(overrides or {})
    return env


def boot_hosted(
    tmp_path: pathlib.Path,
    idp: FakeIdP,
    *,
    surface: str = "console",
    env: dict | None = None,
    clock=None,
    env_overrides: dict | None = None,
) -> HostedAuth:
    resolved_env = (
        env if env is not None else enabled_env(tmp_path, surface=surface, overrides=env_overrides)
    )
    return HostedAuth.boot(
        surface,
        default_state_dir=str(tmp_path / f".hosted-{surface}"),
        env=resolved_env,
        http_get=idp.transport()[0],
        http_post_form=idp.transport()[1],
        clock=clock,
    )


def login_subject(client: TestClient, idp: FakeIdP, hosted: HostedAuth, **claim_kwargs) -> dict:
    """Run the full OIDC flow through the HTTP surface; returns its body."""
    idp.set_claims(**claim_kwargs)
    got = client.get("/api/oidc/login")
    assert got.status_code == 200, got.text
    body = got.json()
    assert body["authorization_url"].startswith(idp.issuer)
    assert "code_challenge_method=S256" in body["authorization_url"]
    assert "nonce=" in body["authorization_url"]
    callback = client.post(
        "/api/oidc/callback",
        json={"code": "auth-code-1", "state": body["state"]},
    )
    assert callback.status_code == 200, callback.text
    opened = callback.json()
    assert opened["token"].startswith(SESSION_TOKEN_PREFIX)
    return opened


class Clock:
    """A controllable epoch clock (seconds)."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def idp() -> FakeIdP:
    return FakeIdP()


# ------------------------------------------------------------------- RBAC units


def test_unknown_role_degrades_to_viewer() -> None:
    assert effective_role([]) == "viewer"
    assert effective_role(["admin"]) == "viewer"  # unknown strings never elevate
    assert effective_role(["operator", "viewer"]) == "viewer"  # rank-min, fail-closed
    assert effective_role(["security-admin", "operator"]) == "operator"
    assert role_allows("operator", "write") is True
    assert role_allows("viewer", "write") is False
    assert role_allows("operator", "security") is False
    assert role_allows("security-admin", "security") is True
    assert role_allows("who-knows", "read") is True  # unknown -> viewer -> read ok
    assert role_allows("who-knows", "write") is False
    assert role_allows("viewer", "mystery-capability") is False  # unknown cap denies


def test_registry_env_grants_and_claim_matching() -> None:
    registry = RoleRegistry({"operator": {"ops@example.org"}})
    assert registry.roles_for(["sub-x", "ops@example.org"]) == ["operator"]
    assert registry.roles_for(["sub-x"]) == []
    assert registry.effective_for(["sub-x"]) == "viewer"


def test_registry_replay_receipt_semantics() -> None:
    registry = RoleRegistry()
    registry.replay_receipt("grant", "sub-x", "operator")
    assert registry.effective_for(["sub-x"]) == "operator"
    registry.replay_receipt("revoke", "sub-x", "operator")
    assert registry.effective_for(["sub-x"]) == "viewer"
    # Unknown / malformed receipts invent no authority (fail-closed).
    registry.replay_receipt("promote", "sub-x", "security-admin")
    registry.replay_receipt("grant", "", "security-admin")
    registry.replay_receipt("grant", "sub-x", "emperor")
    assert registry.effective_for(["sub-x"]) == "viewer"


def test_registry_env_is_the_boot_baseline_and_runtime_extends() -> None:
    registry = RoleRegistry({"viewer": {"sub-env"}})
    registry.replay_receipt("grant", "sub-runtime", "security-admin")
    assert registry.effective_for(["sub-env"]) == "viewer"
    assert registry.effective_for(["sub-runtime"]) == "security-admin"


# ------------------------------------------------------------------- ledger


def test_ledger_chain_and_tamper_detection(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "ledger.jsonl"
    ledger = HostedReceiptLedger(path)
    ledger.load()
    first = ledger.append("session_open", {"session_id": "osn-aa"})
    second = ledger.append("session_close", {"session_id": "osn-aa"})
    assert second["prev_hash"] == first["hash"]
    assert second["index"] == 2  # row 0 is the meta line
    head = ledger.head()

    reloaded = HostedReceiptLedger(path)
    reloaded.load()
    assert reloaded.head() == head
    assert len(reloaded.entries("session_open")) == 1

    # Tamper: rewrite one byte of a middle row => digest chain refuses.
    rows = path.read_text().splitlines()
    row = json.loads(rows[1])
    row["action"] = "session_FORGED"
    rows[1] = json.dumps(row, sort_keys=True)
    path.write_text("\n".join(rows) + "\n")
    tampered = HostedReceiptLedger(path)
    with pytest.raises(LedgerCorruptError):
        tampered.load()


def test_ledger_rows_are_distinct_in_the_same_second(tmp_path: pathlib.Path) -> None:
    import datetime as dt  # noqa: PLC0415 - test-local

    fixed = dt.datetime(2026, 11, 12, 9, 0, 0, tzinfo=dt.UTC)
    ledger = HostedReceiptLedger(
        tmp_path / "ledger.jsonl",
        clock=lambda: fixed,  # same second every time
    )
    ledger.load()
    a = ledger.append("role_change", {"action": "grant", "subject": "a"})
    b = ledger.append("role_change", {"action": "grant", "subject": "a"})
    assert a["hash"] != b["hash"]  # chain index separates same-second events


# ------------------------------------------------------------------- sessions


def opened_session(tmp_path, idp, clock, **claims) -> tuple[object, str]:
    hosted = boot_hosted(tmp_path, idp, clock=clock)
    principal = hosted.principal_from_claims(idp.set_claims(**claims))
    opened = hosted.sessions.open(principal)
    return hosted, opened["token"]


def test_session_open_resolve_and_digest_only_store(tmp_path, idp) -> None:
    clock = Clock()
    hosted, token = opened_session(tmp_path, idp, clock, sub="sub-op", email="op@example.org")
    assert token.startswith(SESSION_TOKEN_PREFIX)
    record = hosted.sessions.resolve_token(token)
    assert record is not None
    assert record["ids"] == ["sub-op", "op@example.org"]
    assert record["session_id"].startswith("osn-")
    # The store holds digests, never tokens: no plaintext credential file.
    ledger_text = (tmp_path / "hosted-state" / "hosted-console-ledger.jsonl").read_text()
    assert token not in ledger_text
    assert "sub-op" in ledger_text  # the receipt binds the subject handle


def test_session_expiry_enforced_then_unresolvable(tmp_path, idp) -> None:
    clock = Clock()
    hosted, token = opened_session(tmp_path, idp, clock)
    assert hosted.sessions.resolve_token(token) is not None
    clock.advance(3601)
    assert hosted.sessions.resolve_token(token) is None
    # Fail-closed on every shape a client can present.
    assert hosted.sessions.resolve_token("garbage") is None
    assert hosted.sessions.resolve_token("") is None
    assert hosted.sessions.resolve_token(None) is None


def test_session_refresh_extends_and_receipts(tmp_path, idp) -> None:
    clock = Clock()
    hosted, token = opened_session(tmp_path, idp, clock)
    before = hosted.sessions.resolve_token(token)["expires_at"]
    clock.advance(600)
    expires_at = hosted.sessions.refresh(token)
    assert expires_at is not None
    assert expires_at > before
    assert hosted.sessions.resolve_token(token) is not None
    # Unknown tokens never refresh.
    assert hosted.sessions.refresh(SESSION_TOKEN_PREFIX + "bogus") is None
    rows = hosted.ledger.entries("session_refresh")
    assert len(rows) == 1
    assert rows[0]["payload"]["subject"] == "sub-console-op"


def test_session_close_receipts_before_drop(tmp_path, idp) -> None:
    hosted, token = opened_session(tmp_path, idp, clock=None)
    assert hosted.sessions.close(token) is True
    assert hosted.sessions.resolve_token(token) is None
    assert hosted.sessions.close(token) is False  # already closed
    assert len(hosted.ledger.entries("session_close")) == 1


def test_session_cap_refuses_fail_closed(tmp_path, idp) -> None:
    env = enabled_env(tmp_path, overrides={"OAA_HOSTED_SESSIONS_MAX": "1"})
    hosted = boot_hosted(tmp_path, idp, env=env)
    first = hosted.sessions.open(hosted.principal_from_claims(idp.set_claims(sub="a")))
    with pytest.raises(SessionOpenError) as excinfo:
        hosted.sessions.open(hosted.principal_from_claims(idp.set_claims(sub="b")))
    assert excinfo.value.status == 503
    assert "session limit" in excinfo.value.reason
    del first


# ------------------------------------------------------------------- config


def test_disabled_by_default_and_flag_validation(tmp_path) -> None:
    from oaa_hosted_auth import parse_enabled  # noqa: PLC0415 - test-local
    from oaa_hosted_auth.config import from_env_for_surface  # noqa: PLC0415 - test-local

    assert parse_enabled({}) is False
    with pytest.raises(HostedOIDCError) as excinfo:
        parse_enabled({"OAA_HOSTED_OIDC_ENABLED": "sure"})
    assert OIDC_CONFIG_ERROR in str(excinfo.value)
    cfg = from_env_for_surface(
        "OAA_HOSTED_OIDC_REDIRECT_URI_CONSOLE", env={}, default_state_dir="x"
    )
    assert cfg.session_ttl == 3600
    assert cfg.sessions_max == 64
    assert cfg.issuer == ""  # disabled surfaces carry no provider config


@pytest.mark.parametrize(
    "overrides",
    [
        {"OAA_HOSTED_OIDC_ISSUER": "http://idp.example.org"},
        {"OAA_HOSTED_OIDC_ISSUER": ""},
        {"OAA_HOSTED_OIDC_CLIENT_ID": ""},
        {"OAA_HOSTED_OIDC_CLIENT_SECRET": ""},
        {"OAA_HOSTED_SESSION_TTL": "30"},
        {"OAA_HOSTED_SESSION_TTL": "abc"},
        {"OAA_HOSTED_SESSIONS_MAX": "0"},
        {"OAA_HOSTED_OIDC_REDIRECT_URI_CONSOLE": ""},
    ],
)
def test_enabled_config_failures_refuse_boot(tmp_path, idp, overrides: dict) -> None:
    env = enabled_env(tmp_path, surface="console", overrides=overrides)
    with pytest.raises(HostedOIDCError) as excinfo:
        boot_hosted(tmp_path, idp, env=env)
    assert OIDC_CONFIG_ERROR in str(excinfo.value)


def test_secret_file_contract(tmp_path, idp) -> None:
    secret_file = tmp_path / "hosted-secret"
    secret_file.write_text(CLIENT_SECRET)
    secret_file.chmod(0o600)
    env = enabled_env(tmp_path)
    env.pop("OAA_HOSTED_OIDC_CLIENT_SECRET")
    env["OAA_HOSTED_OIDC_CLIENT_SECRET_FILE"] = str(secret_file)
    hosted = boot_hosted(tmp_path, idp, env=env)
    assert hosted.enabled is True
    # A looser file refuses rather than reads (fail-closed 0600 contract).
    secret_file.chmod(0o644)
    with pytest.raises(HostedOIDCError) as excinfo:
        boot_hosted(tmp_path, idp, env=env)
    assert OIDC_CONFIG_ERROR in str(excinfo.value)
    assert "0600" in str(excinfo.value)


# ------------------------------------------------------------------- discovery


def test_discovery_failures_refuse_boot(tmp_path, idp) -> None:
    # issuer identity must match exactly (RFC 8414 3.3)
    idp.discovery_doc = {**idp.discovery(), "issuer": ISSUER + "/"}
    with pytest.raises(HostedOIDCError) as excinfo:
        boot_hosted(tmp_path, idp)
    assert OIDC_DISCOVERY_ERROR in str(excinfo.value)

    # plaintext endpoints in the discovery document refuse
    idp.discovery_doc = {**idp.discovery(), "jwks_uri": "http://idp.example.org/jwks.json"}
    with pytest.raises(HostedOIDCError) as excinfo:
        boot_hosted(tmp_path, idp)
    assert OIDC_DISCOVERY_ERROR in str(excinfo.value)

    # a JWKS without usable RSA keys refuses
    idp.discovery_doc = None
    idp.jwks_doc = {"keys": [{"kty": "oct", "kid": "x"}]}
    with pytest.raises(HostedOIDCError) as excinfo:
        boot_hosted(tmp_path, idp)
    assert OIDC_DISCOVERY_ERROR in str(excinfo.value)

    # an unreachable discovery endpoint refuses (fail-closed banner contract)
    idp.jwks_doc = None
    idp.get_error = OSError("connection refused")
    with pytest.raises(HostedOIDCError) as excinfo:
        boot_hosted(tmp_path, idp)
    assert OIDC_DISCOVERY_ERROR in str(excinfo.value)


# ------------------------------------------------------------- HTTP flow


def enabled_console(tmp_path: pathlib.Path, idp: FakeIdP, **env_overrides) -> TestClient:
    """An enabled console app + its injected provider transport."""
    sys.path.insert(0, str(REPO_ROOT / "services" / "console" / "src"))
    from raucle_console.app import create_app as create_console_app  # noqa: PLC0415 - test-local

    env = enabled_env(tmp_path, surface="console", overrides=env_overrides or None)
    hosted = boot_hosted(tmp_path, idp, env=env)
    return TestClient(create_console_app(hosted=hosted), raise_server_exceptions=False)


def test_oidc_login_and_callback_happy_path(tmp_path, idp) -> None:
    from urllib.parse import parse_qs, urlparse  # noqa: PLC0415 - test-local

    client = enabled_console(tmp_path, idp)
    login = client.get("/api/oidc/login")
    assert login.status_code == 200
    url = login.json()["authorization_url"]
    assert url.startswith(idp.issuer + "/authorize")
    params = parse_qs(urlparse(url).query)
    assert params["response_type"] == ["code"]
    assert params["code_challenge_method"] == ["S256"]
    assert params["client_id"] == ["hosted-console"]
    assert params["redirect_uri"] == ["http://127.0.0.1:3412/"]
    assert params["scope"] == ["openid profile email"]
    assert params["nonce"]
    assert params["state"]
    assert params["code_challenge"]

    idp.set_claims(sub="sub-console-op", email="op@example.org", nonce=params["nonce"][0])
    callback = client.post("/api/oidc/callback", json={"code": "c", "state": login.json()["state"]})
    assert callback.status_code == 200, callback.text
    body = callback.json()
    assert body["session_token"].startswith(SESSION_TOKEN_PREFIX)
    assert body["auth_method"] == "oidc"
    assert body["role"] == "viewer"  # unlisted subject: fail-closed view-only
    assert body["subject"] == "sub-console-op"
    me = client.get("/api/session/me", headers={"Authorization": f"Bearer {body['session_token']}"})
    assert me.status_code == 200
    assert me.json()["role"] == "viewer"
    assert me.json()["subject"] == "sub-console-op"
    # No provider artefact ever echoes: the id_token stays server-side.
    assert "id_token" not in json.dumps(body)
    assert "signature" not in json.dumps(body)


def _run_login(client: TestClient, idp: FakeIdP, **claim_kwargs) -> dict:
    """Login -> callback with the URL-bound nonce; returns the callback body
    plus the single-use login ``state`` (for replay assertions)."""
    from urllib.parse import parse_qs, urlparse  # noqa: PLC0415 - test-local

    login = client.get("/api/oidc/login")
    assert login.status_code == 200
    nonce = parse_qs(urlparse(login.json()["authorization_url"]).query)["nonce"][0]
    idp.set_claims(nonce=nonce, **claim_kwargs)
    callback = client.post("/api/oidc/callback", json={"code": "c", "state": login.json()["state"]})
    assert callback.status_code == 200, callback.text
    return {**callback.json(), "state": login.json()["state"]}


def test_oidc_state_single_use_and_unknown_state(tmp_path, idp) -> None:
    client = enabled_console(tmp_path, idp)
    body = _run_login(client, idp, sub="sub-op")
    assert body["session_token"].startswith(SESSION_TOKEN_PREFIX)
    replay = client.post("/api/oidc/callback", json={"code": "c", "state": body["state"]})
    assert replay.status_code == 401
    assert OIDC_EXCHANGE_ERROR in replay.json()["detail"]["error"]
    unknown = client.post("/api/oidc/callback", json={"code": "c", "state": "oidc_nope"})
    assert unknown.status_code == 401
    assert OIDC_EXCHANGE_ERROR in unknown.json()["detail"]["error"]
    # A provider error param is a 401 with the provider's reason surfaced.
    refused = client.post(
        "/api/oidc/callback", json={"error": "access_denied", "error_description": "no"}
    )
    assert refused.status_code == 401
    assert "access_denied" in refused.json()["detail"]["error"]


@pytest.mark.parametrize(
    "claims_overrides,mint_kwargs,expected_fragment",
    [
        (None, {"key": "wrong"}, "signature verification failed"),
        ({"aud": "another-client"}, {}, "audience"),
        ({"iss": "https://evil.example.org"}, {}, "issuer"),
        ({"exp": 0}, {}, "expired"),
        ({"nonce": "stale-nonce"}, {}, "nonce"),
        (None, {"alg": "HS256"}, "only RS256"),
        ({"sub": ""}, {}, "sub claim"),
    ],
)
def test_oidc_bad_id_tokens_refuse_any_session(
    tmp_path, idp, claims_overrides: dict | None, mint_kwargs: dict, expected_fragment: str
) -> None:
    from urllib.parse import parse_qs, urlparse  # noqa: PLC0415 - test-local

    client = enabled_console(tmp_path, idp)
    login = client.get("/api/oidc/login").json()
    params = parse_qs(urlparse(login["authorization_url"]).query)
    claims = idp.set_claims(
        sub="sub-op",
        email="ops@example.org",
        nonce=params["nonce"][0],
    )
    if claims_overrides:
        claims = {**claims, **claims_overrides}
    mint_args: dict = {}
    if mint_kwargs.get("key") == "wrong":
        mint_args["key"] = idp.wrong_key
    if mint_kwargs.get("alg"):
        mint_args["alg"] = mint_kwargs["alg"]
    idp.token_payload_override = {"id_token": idp.mint(claims, **mint_args)}
    callback = client.post("/api/oidc/callback", json={"code": "c", "state": login["state"]})
    assert callback.status_code == 401, callback.text
    error = callback.json()["detail"]["error"]
    assert OIDC_EXCHANGE_ERROR in error
    assert expected_fragment in error


def test_oidc_exchange_transport_failures_and_missing_id_token(tmp_path, idp) -> None:
    client = enabled_console(tmp_path, idp)
    idp.set_claims(sub="sub-op")

    idp.token_payload_override = {"access_token": "at"}  # no id_token in response
    state = client.get("/api/oidc/login").json()["state"]
    r = client.post("/api/oidc/callback", json={"code": "c", "state": state})
    assert r.status_code == 401
    assert OIDC_EXCHANGE_ERROR in r.json()["detail"]["error"]

    idp.token_payload_override = None
    idp.token_error = OSError("token endpoint unreachable")
    state = client.get("/api/oidc/login").json()["state"]
    r = client.post("/api/oidc/callback", json={"code": "c", "state": state})
    assert r.status_code == 401
    assert "token exchange failed" in r.json()["detail"]["error"]

    # Undecodable token segments never become a session.
    idp.token_error = None
    idp.token_payload_override = {"id_token": "not-a-jws"}
    state = client.get("/api/oidc/login").json()["state"]
    r = client.post("/api/oidc/callback", json={"code": "c", "state": state})
    assert r.status_code == 401
    assert OIDC_EXCHANGE_ERROR in r.json()["detail"]["error"]


def test_oidc_client_secret_missing_at_exchange_fails_named(tmp_path, idp) -> None:
    # A boot-valid (present) but implausibly short secret exchanges nothing.
    client = enabled_console(tmp_path, idp, OAA_HOSTED_OIDC_CLIENT_SECRET="short")
    idp.set_claims(sub="sub-op")
    state = client.get("/api/oidc/login").json()["state"]
    r = client.post("/api/oidc/callback", json={"code": "c", "state": state})
    assert r.status_code == 401
    assert OIDC_CONFIG_ERROR in r.json()["detail"]["error"]


def test_disabled_console_keeps_legacy_open_behaviour(tmp_path: pathlib.Path, idp: FakeIdP) -> None:
    client = enabled_console(tmp_path, idp, **{"OAA_HOSTED_OIDC_ENABLED": "0"})
    assert client.get("/api/overview").status_code == 200  # legacy open surface
    config = client.get("/api/session/config")
    assert config.status_code == 200
    assert config.json() == {"oidc_enabled": False, "surface": "console"}
    # No session routes exist when auth is off: there is nothing to keep.
    assert client.get("/api/oidc/login").status_code == 404
    assert client.post("/api/session/logout").status_code == 404
    assert client.get("/api/session/me").status_code == 404
    assert (
        client.post(
            "/api/roles/anything", json={"action": "grant", "role": "operator", "reason": "r"}
        ).status_code
        == 404
    )


def test_enabled_fail_closed_on_every_data_route(tmp_path, idp) -> None:
    client = enabled_console(tmp_path, idp)
    console_read = client.get("/api/overview")
    assert console_read.status_code == 403
    assert console_read.json()["detail"]["error"] == "authentication required"
    assert console_read.json()["detail"]["auth_required"] is True
    for path in (
        "/api/config",
        "/api/trends",
        "/api/red/dogfood",
        "/api/red/targets",
        "/api/red/status",
        "/api/red/results",
        "/api/assurance/dashboard",
        "/api/assurance/counts",
        "/api/assurance/findings",
        "/api/assurance/findings/red",
        "/api/roles",
    ):
        assert client.get(path).status_code == 403, path
    # POSTs too, before any proxying happens.
    for path in ("/api/red/run", "/api/red/stop", "/api/assurance/findings/ingest"):
        assert client.post(path, json={}).status_code == 403, path
    # The data-free shells stay reachable so the SPA can boot itself.
    assert client.get("/").status_code == 200
    assert client.get("/static/index.html").status_code == 200
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/not/in-the/matrix").status_code == 403
    assert (
        "not in the hosted permission matrix"
        in client.get("/api/not/in-the/matrix").json()["error"]
    )
    # Auto-generated docs stay exempt in enabled mode (documented decision).
    assert client.get("/openapi.json").status_code == 200


def test_session_config_never_echoes_secret_or_role_env(tmp_path, idp) -> None:
    client = enabled_console(tmp_path, idp)
    body = json.dumps(client.get("/api/session/config").json())
    assert "provider_issuer" in body  # gateway-compatible shape
    assert CLIENT_SECRET not in body


def test_logout_and_refresh_over_http(tmp_path, idp) -> None:
    client = enabled_console(tmp_path, idp)
    body = _run_login(client, idp, sub="sub-op")
    token = body["session_token"]
    headers = {"Authorization": f"Bearer {token}"}
    refreshed = client.post("/api/session/refresh", headers=headers)
    assert refreshed.status_code == 200
    assert refreshed.json()["subject"] == "sub-op"
    closed = client.post("/api/session/logout", headers=headers)
    assert closed.status_code == 200
    # The dead token is exactly like no token: fail closed.
    assert client.post("/api/session/refresh", headers=headers).status_code == 403
    assert client.get("/api/session/me", headers=headers).status_code == 403
    assert client.post("/api/session/logout", headers=headers).status_code == 403
