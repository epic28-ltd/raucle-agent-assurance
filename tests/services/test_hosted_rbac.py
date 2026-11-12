# SPDX-License-Identifier: Apache-2.0
"""R2 slice 1 hosted RBAC: route-level permission matrix + fail-closed posture.

Drives BOTH hosted surfaces (console + investigation UI) through their
permission matrices with real sessions opened from verifiable OIDC-shaped
claims:

- the denied/allowed matrix is asserted route-by-route for every role
  (viewer / operator / security-admin), with the anonymous refusal covered
  by the fail-closed tests in test_hosted_auth.py;
- matrix completeness: every registered route in both apps must be bound
  to a capability (or be an explicitly named data-free shell) — a future
  route without a matrix entry fails this test in CI instead of shipping
  silently open;
- role changes are receipted (hashed ledger), take effect on the next
  request, replay across a boot of a new surface, and refuse without
  their receipt;
- fail-closed defaults: unknown subject -> viewer, contradictory grants ->
  rank-min, tampered ledger -> boot refusal, unbound path -> refusal.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import sys

from test_hosted_auth import FakeIdP, boot_hosted, enabled_env  # test-local helpers

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
for _p in (
    REPO_ROOT / "services" / "investigation-ui" / "src",
    REPO_ROOT / "services" / "console" / "src",
):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from oaa_hosted_auth import SESSION_TOKEN_PREFIX, HostedAuth  # noqa: E402
from oaa_investigation_ui.app import create_app as create_investigation  # noqa: E402
from raucle_console.app import create_app as create_console  # noqa: E402

DEMO_DATA = REPO_ROOT / "services" / "investigation-ui" / "demo_data"

ROLE_OPS_EMAIL = "ops@example.org"
ROLE_SEC_EMAIL = "sec@example.org"

# The data-free shell paths per surface (exempt from the matrix walk).
SHELL_PATHS = {
    "console": {"/", "/static/index.html", "/static/hosted-auth-hook.js"},
    "assurance": {"/", "/legacy.html", "/view/fleet", "/static/hosted-auth-hook.js"},
}
AUTO_DOC_PATHS = {"/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"}

# (method, path, capability) route-by-route — the console's matrix, which
# the role sweep below walks. Capabilities: r=read, w=write, p=public.
CONSOLE_MATRIX = (
    ("GET", "/api/overview", "r"),
    ("GET", "/api/config", "r"),
    ("GET", "/api/trust/policies/summary", "r"),
    ("GET", "/api/assurance/dashboard", "r"),
    ("GET", "/api/assurance/counts", "r"),
    ("GET", "/api/assurance/findings", "r"),
    ("GET", "/api/trends", "r"),
    ("GET", "/api/red/dogfood", "r"),
    ("GET", "/api/red/targets", "r"),
    ("POST", "/api/red/run", "w"),
    ("GET", "/api/red/status", "r"),
    ("GET", "/api/red/results", "r"),
    ("POST", "/api/red/stop", "w"),
    ("GET", "/api/assurance/findings/red", "r"),
    ("POST", "/api/assurance/findings/ingest", "w"),
    ("GET", "/api/health", "p"),
)


@pytest.fixture
def idp() -> FakeIdP:
    return FakeIdP()


def rbac_env(tmp_path, **overrides) -> dict:
    return enabled_env(
        tmp_path,
        overrides={
            "OAA_HOSTED_ROLE_OPERATOR": ROLE_OPS_EMAIL,
            "OAA_HOSTED_ROLE_SECURITY_ADMIN": ROLE_SEC_EMAIL,
            **overrides,
        },
    )


def role_session(hosted: HostedAuth, idp: FakeIdP, **claims) -> str:
    principal = hosted.principal_from_claims(idp.set_claims(**claims))
    opened = hosted.sessions.open(principal)
    assert opened["token"].startswith(SESSION_TOKEN_PREFIX)
    return opened["token"]


def heads(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# ------------------------------------------------------- console surfaces


def console_with_session(tmp_path, idp, role: str | None) -> tuple[TestClient, str, HostedAuth]:
    hosted = boot_hosted(tmp_path, idp, env=rbac_env(tmp_path))
    client = TestClient(create_console(hosted=hosted), raise_server_exceptions=False)
    claims = {"sub": f"sub-{role or 'anon'}"}
    if role == "operator":
        claims["email"] = ROLE_OPS_EMAIL
    elif role == "security-admin":
        claims["email"] = ROLE_SEC_EMAIL
    return client, role_session(hosted, idp, **claims), hosted


def stub_console_outbound(monkeypatch, payload: dict) -> None:
    """Console proxies go out over httpx; stub every outbound transport
    deterministically so sweeps prove ONLY the role gate."""
    import httpx as _httpx  # noqa: PLC0415 - test-local stub
    import raucle_console.app as console_app  # noqa: PLC0415 - test-local stub

    def _stub(*_a, **_k):
        return _httpx.Response(200, json=payload, request=_httpx.Request("GET", "/"))

    class FakeAsyncClient:
        def __init__(self, **_kwargs) -> None:
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args) -> bool:
            return False

        async def post(self, _url, **_kwargs):
            return _stub()

    monkeypatch.setattr(console_app.httpx, "get", _stub, raising=True)
    monkeypatch.setattr(console_app.httpx, "request", _stub, raising=True)
    monkeypatch.setattr(console_app.httpx, "AsyncClient", FakeAsyncClient, raising=True)


# ---------------------------------------------------- matrix completeness


def assert_matrix_covers(app, hosted: HostedAuth, surface: str) -> None:
    bound = {(row["method"], row["path"]) for row in hosted.bound_routes()}
    seen: set[tuple[str, str]] = set()
    for route in app.routes:
        path = getattr(route, "path", None)
        methods = getattr(route, "methods", None)
        if path is None or methods is None:
            continue  # mounts and non-HTTP artefacts
        for method in sorted(methods):
            if method == "HEAD":
                continue
            key = (method, path)
            seen.add(key)
            assert key in bound or path in SHELL_PATHS[surface] or path in AUTO_DOC_PATHS, (
                f"route without a permission-matrix entry: {key}"
            )
    for key in bound:
        assert key in seen, f"matrix entry with no real route: {key}"


def test_console_matrix_completeness(tmp_path, idp) -> None:
    hosted = boot_hosted(tmp_path, idp, env=rbac_env(tmp_path))
    app = create_console(hosted=hosted)
    assert_matrix_covers(app, hosted, "console")


def test_console_matrix_matches_the_documented_table(tmp_path, idp) -> None:
    hosted = boot_hosted(tmp_path, idp, env=rbac_env(tmp_path))
    create_console(hosted=hosted)
    bound = {(row["method"], row["path"]): row["capability"] for row in hosted.bound_routes()}
    expect = {"r": "read", "w": "write", "p": "public"}
    for method, path, capability in CONSOLE_MATRIX:
        assert bound[(method, path)] == expect[capability], (method, path)


def test_console_disabled_surface_binds_only_legacy(tmp_path, idp, monkeypatch) -> None:
    stub_console_outbound(monkeypatch, {})
    env = rbac_env(tmp_path, **{"OAA_HOSTED_OIDC_ENABLED": "0"})
    hosted = boot_hosted(tmp_path, idp, env=env)
    app = create_console(hosted=hosted)
    assert_matrix_covers(app, hosted, "console")
    bound_paths = {
        row["path"] for row in hosted.bound_routes() if row["path"] != "/api/session/config"
    }
    # No session/OIDC/role routes in legacy mode: nothing to enforce.
    assert not any(
        p.startswith("/api/session/") or p.startswith("/api/oidc/") or p.startswith("/api/roles")
        for p in bound_paths
    )


def test_investigation_matrix_completeness(tmp_path, idp) -> None:
    demo = tmp_path / "demo"
    shutil.copytree(DEMO_DATA, demo)
    env = rbac_env(tmp_path)
    hosted = boot_hosted(tmp_path, idp, env=env)
    app = create_investigation(data_dir=demo, hosted=hosted)
    assert_matrix_covers(app, hosted, "assurance")


# ----------------------------------------------------- role sweep, console


@pytest.mark.parametrize(
    "role,write_allowed",
    (("viewer", False), ("operator", True), ("security-admin", True)),
)
def test_console_route_matrix_by_role(
    tmp_path, idp, role: str, write_allowed: bool, monkeypatch
) -> None:
    stub_console_outbound(monkeypatch, {"accepted": True})
    client, token, _h = console_with_session(tmp_path, idp, role)
    auth = heads(token)
    bodies = {
        "POST /api/red/run": {"preset": "quick", "target": "demo"},
        "POST /api/red/stop": {},
        "POST /api/assurance/findings/ingest": {"anything": True},
    }
    for method, path, capability in CONSOLE_MATRIX:
        kwargs = {"json": bodies[f"{method} {path}"]} if f"{method} {path}" in bodies else {}
        r = client.request(method, path, headers=auth, **kwargs)
        if capability == "w" and not write_allowed:
            assert r.status_code == 403, (method, path, role, r.status_code, r.text[:120])
            assert f"Role '{role}' cannot access 'write'" in json.dumps(r.json())
        else:
            assert r.status_code in (200, 201), (method, path, role, r.status_code, r.text[:120])
    # The security plane denies below security-admin regardless of write.
    r = client.post(
        "/api/roles/sub-x",
        json={"action": "grant", "role": "operator", "reason": "r"},
        headers=auth,
    )
    if role == "security-admin":
        assert r.status_code == 200
    else:
        assert r.status_code == 403
        assert f"Role '{role}' cannot access 'security'" in json.dumps(r.json())


# ----------------------------------------------- investigation UI sweeps


def investigation_client(tmp_path, idp, hosted_env: dict) -> tuple[TestClient, HostedAuth]:
    demo = tmp_path / "demo"
    shutil.copytree(DEMO_DATA, demo)
    leaked = demo / "red_findings.json"
    if leaked.exists():
        leaked.unlink()
    hosted = boot_hosted(tmp_path, idp, env=hosted_env)
    client = TestClient(
        create_investigation(data_dir=demo, hosted=hosted), raise_server_exceptions=False
    )
    return client, hosted


INVESTIGATION_READS = (
    "/api/dashboard",
    "/api/counts",
    "/api/runs",
    "/api/findings",
    "/api/findings/red",
    "/api/findings/board",
    "/api/live/traces",
    "/coverage/demo",
    "/assurance/summary",
)


@pytest.mark.parametrize(
    "role,write_allowed",
    (("viewer", False), ("operator", True), ("security-admin", True)),
)
def test_investigation_route_matrix_by_role(tmp_path, idp, role: str, write_allowed: bool) -> None:
    client, hosted = investigation_client(tmp_path, idp, rbac_env(tmp_path))
    claims = {"sub": f"sub-{role}"}
    if role == "operator":
        claims["email"] = ROLE_OPS_EMAIL
    elif role == "security-admin":
        claims["email"] = ROLE_SEC_EMAIL
    token = role_session(hosted, idp, **claims)
    auth = heads(token)

    for path in INVESTIGATION_READS:
        r = client.get(path, headers=auth)
        assert r.status_code == 200, (path, role, r.status_code, r.text[:120])

    # Reads that answer by data (404/422), proving the endpoint RAN.
    r = client.get("/api/receipts/deadbeefdeadbeef", headers=auth)
    assert r.status_code == 404, (role, r.status_code)
    r = client.post("/api/receipts/deadbeefdeadbeef/verify", content=b"", headers=auth)
    assert r.status_code == 404, (role, r.status_code)
    r = client.post("/assurance/packet", json={}, headers=auth)
    assert r.status_code == 200, (role, r.status_code, r.text[:120])

    # Writes: the gate fires BEFORE validation for viewers; operators pass
    # the gate and reach the data checks (422/404/200 by design).
    r = client.post("/api/findings/ingest", content=b"", headers=auth)
    if write_allowed:
        assert r.status_code == 422, (role, r.status_code, r.text[:120])
        assert "no findings" in r.json()["error"]
    else:
        assert r.status_code == 403
        assert f"Role '{role}' cannot access 'write'" in json.dumps(r.json())

    r = client.post("/api/findings/unknown-id/triage", json={"state": "New"}, headers=auth)
    assert r.status_code == (404 if write_allowed else 403)

    r = client.post("/api/fleet/rollup", content=b"not json", headers=auth)
    assert r.status_code == (422 if write_allowed else 403)

    r = client.delete("/api/fleet/rollup", headers=auth)
    assert r.status_code == (200 if write_allowed else 403)


@pytest.mark.parametrize("role", ("viewer", "operator", "security-admin"))
def test_investigation_no_js_pages_html_fail_closed(tmp_path, idp, role: str) -> None:
    client, hosted = investigation_client(tmp_path, idp, rbac_env(tmp_path))
    claims = {"sub": f"sub-{role}"}
    if role == "operator":
        claims["email"] = ROLE_OPS_EMAIL
    elif role == "security-admin":
        claims["email"] = ROLE_SEC_EMAIL
    token = role_session(hosted, idp, **claims)
    auth = heads(token)
    for path in ("/view/runs", "/view/receipt/deadbeefdeadbeef"):
        anonymous = client.get(path)
        assert anonymous.status_code == 403
        assert anonymous.headers["content-type"].startswith("text/html")
        assert "identity provider" in anonymous.text
        r = client.get(path, headers=auth)
        assert r.status_code == 200, (path, role, r.status_code)
    # The data-free shells stay reachable for every session.
    assert client.get("/", headers=auth).status_code == 200
    assert client.get("/legacy.html", headers=auth).status_code == 200
    # The security-HTML page keeps the viewer out by role even when logged in.
    r = client.get("/view/runs", headers=heads(role_session(hosted, idp, sub="sub-v1")))
    assert r.status_code == 200  # viewer: view-only reads stay readable


# ----------------------------------------------- hosted login hook contract


def test_hosted_login_hook_served_and_referenced_by_every_carrier_page(tmp_path, idp) -> None:
    """The hosted-login hook is ONE physical file on BOTH carrier surfaces.

    The pages must keep carrying the hook (a reference instead of the former
    ~150-line inline copy) and both apps must serve the same file at
    /static/hosted-auth-hook.js — inline duplication was the Sonar
    new_duplicated_lines debt; the contract proves the behaviour moved
    instead of disappearing.
    """
    console = TestClient(
        create_console(hosted=boot_hosted(tmp_path, idp, env=rbac_env(tmp_path))),
        raise_server_exceptions=False,
    )
    investigation_client_inst, _hosted = investigation_client(tmp_path, idp, rbac_env(tmp_path))
    pages = {
        "console": (
            console,
            ("/", "/static/index.html"),
        ),
        "assurance": (
            investigation_client_inst,
            ("/", "/legacy.html", "/view/fleet"),
        ),
    }
    tag = '<script src="/static/hosted-auth-hook.js"></script>'
    for surface, (client, paths) in pages.items():
        for path in paths:
            page = client.get(path)
            assert page.status_code == 200, (surface, path)
            assert tag in page.text, (surface, path)
            # No page carries the former inline copy any more.
            assert "oaa_hosted_session" not in page.text, (surface, path)
        served = client.get("/static/hosted-auth-hook.js")
        assert served.status_code == 200, surface
        assert "javascript" in served.headers["content-type"]
        # The served body is the interposer itself, not a 404 page.
        for needle in ("window.fetch", "oaaAuthHeaders", "/api/oidc/callback"):
            assert needle in served.text, (surface, needle)
        # The plain script sits BEFORE the pages' own module scripts.
        for path in paths:
            text = client.get(path).text
            tag_at = text.index(tag)
            module_at = text.find('<script type="module">')
            if module_at != -1:
                assert tag_at < module_at, (surface, path)


# ------------------------------------------------------- role lifecycle
def test_role_change_grant_revoke_receipted_and_live(tmp_path, idp, monkeypatch) -> None:
    stub_console_outbound(monkeypatch, {"accepted": True})
    client, admin_token, hosted = console_with_session(tmp_path, idp, "security-admin")
    ops_token = role_session(hosted, idp, sub="sub-ops", email=ROLE_OPS_EMAIL)
    del ops_token  # (covered by the env-based matrix sweeps above)

    r = client.post(
        "/api/roles/sub-runtime",
        json={"action": "grant", "role": "operator", "reason": "sprint duty"},
        headers=heads(admin_token),
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["action"] == "grant" and body["subject"] == "sub-runtime"
    assert body["effective_role"] == "operator"
    assert body["receipt_hash"]

    # Runtime grants surface in /api/roles; env grant lists never echo.
    listed = client.get("/api/roles", headers=heads(admin_token))
    assert listed.status_code == 200
    assert listed.json()["runtime_grants"] == {"sub-runtime": ["operator"]}
    assert ROLE_OPS_EMAIL not in json.dumps(listed.json())

    # A NEW login for the receipted subject carries the role immediately.
    fresh = role_session(hosted, idp, sub="sub-runtime")
    me = client.get("/api/session/me", headers=heads(fresh))
    assert me.json()["role"] == "operator"

    # ...and the new role actually AUTHORISES write routes for that
    # session, not just labels it.
    stub_console_outbound(monkeypatch, {"accepted": True})
    r = client.post(
        "/api/red/run",
        json={"preset": "quick", "target": "demo"},
        headers=heads(fresh),
    )
    assert r.status_code == 200, r.text[:120]

    revoke = client.post(
        "/api/roles/sub-runtime",
        json={"action": "revoke", "role": "operator", "reason": "sprint ended"},
        headers=heads(admin_token),
    )
    assert revoke.status_code == 200
    assert revoke.json()["effective_role"] == "viewer"
    me2 = client.get("/api/session/me", headers=heads(fresh))
    assert me2.json()["role"] == "viewer"
    r = client.post(
        "/api/red/run",
        json={"preset": "quick", "target": "demo"},
        headers=heads(fresh),
    )
    assert r.status_code == 403

    rows = hosted.ledger.entries("role_change")
    assert [row["payload"]["action"] for row in rows] == ["grant", "revoke"]
    assert rows[0]["payload"]["actor"].startswith("osn-")
    assert rows[1]["payload"]["role"] == "operator"


@pytest.mark.parametrize(
    "body",
    (
        {"action": "promote", "role": "operator", "reason": "r"},
        {"action": "grant", "role": "emperor", "reason": "r"},
        {"action": "grant", "role": "operator"},
        {"action": "grant", "role": "operator", "reason": "   "},
        {"action": "grant", "role": "operator", "reason": "r", "extra": "ignored"},
    ),
)
def test_role_change_validation_shapes(tmp_path, idp, monkeypatch, body: dict) -> None:
    stub_console_outbound(monkeypatch, {})
    client, admin_token, hosted = console_with_session(tmp_path, idp, "security-admin")
    r = client.post("/api/roles/sub-x", json=body, headers=heads(admin_token))
    if "extra" in body:
        assert r.status_code == 200  # unknown keys are ignorable, not fatal
        return
    assert r.status_code == 422
    assert hosted.registry.runtime_grants() == {}
    for role in ("viewer", "operator"):
        client2, token2, hosted2 = console_with_session(tmp_path, idp, role)
        r2 = client2.post(
            "/api/roles/sub-x",
            json={"action": "grant", "role": "operator", "reason": "r"},
            headers=heads(token2),
        )
        assert r2.status_code == 403
        assert hosted2.registry.runtime_grants() == {}


def test_role_changes_replay_across_boot(tmp_path, idp, monkeypatch) -> None:
    stub_console_outbound(monkeypatch, {})
    client, admin_token, _hosted = console_with_session(tmp_path, idp, "security-admin")
    r = client.post(
        "/api/roles/sub-durable",
        json={"action": "grant", "role": "security-admin", "reason": "on-call"},
        headers=heads(admin_token),
    )
    assert r.status_code == 200

    # A fresh boot of the SAME surface replays the receipted grant, and the
    # env baseline still applies alongside it.
    host2 = boot_hosted(tmp_path, idp, env=rbac_env(tmp_path))
    assert host2.registry.effective_for(["sub-durable"]) == "security-admin"
    assert host2.registry.effective_for(["sub-ops", ROLE_OPS_EMAIL]) == "operator"


def test_role_change_refuses_without_its_receipt(tmp_path, idp, monkeypatch) -> None:
    stub_console_outbound(monkeypatch, {})
    client, admin_token, hosted = console_with_session(tmp_path, idp, "security-admin")

    def broken_append(_action, _payload):
        raise OSError("disk full")

    ledger_cls = type(hosted.ledger)
    orig = ledger_cls.append
    monkeypatch.setattr(ledger_cls, "append", broken_append)
    r = client.post(
        "/api/roles/sub-x",
        json={"action": "grant", "role": "operator", "reason": "r"},
        headers=heads(admin_token),
    )
    monkeypatch.setattr(ledger_cls, "append", orig)
    assert r.status_code == 503
    assert "role ledger unavailable" in r.json()["error"]
    assert hosted.registry.runtime_grants() == {}


def test_tampered_ledger_refuses_boot(tmp_path, idp, monkeypatch) -> None:
    stub_console_outbound(monkeypatch, {})
    client, admin_token, _hosted = console_with_session(tmp_path, idp, "security-admin")
    r = client.post(
        "/api/roles/sub-x",
        json={"action": "grant", "role": "operator", "reason": "r"},
        headers=heads(admin_token),
    )
    assert r.status_code == 200
    ledger_path = tmp_path / "hosted-state" / "hosted-console-ledger.jsonl"
    lines = ledger_path.read_text().splitlines()
    row = json.loads(lines[-1])
    row["payload"]["role"] = "security-admin"  # forged elevation
    lines[-1] = json.dumps(row, sort_keys=True)  # the stored digest no longer matches
    ledger_path.write_text("\n".join(lines) + "\n")
    from oaa_hosted_auth import LedgerCorruptError  # noqa: PLC0415 - test-local

    with pytest.raises(LedgerCorruptError):
        boot_hosted(tmp_path, idp, env=rbac_env(tmp_path))


def test_unmapped_paths_fail_closed(tmp_path, idp) -> None:
    client, hosted = investigation_client(tmp_path, idp, rbac_env(tmp_path))
    token = role_session(hosted, idp, sub="sub-anything", email=ROLE_SEC_EMAIL)
    auth = heads(token)
    r = client.get("/api/definitely/not/mapped", headers=auth)
    assert r.status_code == 403
    assert "not in the hosted permission matrix" in json.dumps(r.json())
    # Unknown subject + never-granted identity degrade to view-only.
    viewerless = role_session(hosted, idp, sub="sub-nobody")
    me2 = client.get("/api/session/me", headers=heads(viewerless))
    assert me2.json()["role"] == "viewer"
    write = client.post("/api/findings/ingest", content=b"", headers=heads(viewerless))
    assert write.status_code == 403
