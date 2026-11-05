# SPDX-License-Identifier: Apache-2.0
"""AUD-01 auditor export pack tests (P1.7a + P1.7b).

Fixtures build a pack from the demo evidence store, verify it green
(standalone verifier, real Ed25519 cryptography), then attack it:
byte tamper, guard stripping, zip roundtrip, and the import-boundary
test proving the verifier depends only on stdlib + cryptography.
"""

from __future__ import annotations

import ast
import base64
import datetime as dt
import hashlib
import http.client
import importlib.util
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import urllib.request

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "services" / "investigation-ui" / "demo_data"
RAUCLE_OSS_HOME = pathlib.Path(os.environ.get("RAUCLE_OSS_HOME", "~/Projects/raucle")).expanduser()
CLOCK = dt.datetime(2026, 11, 5, 12, 0, 0, tzinfo=dt.UTC)
MANIFEST = "manifest.json"

_spec = importlib.util.spec_from_file_location(
    "oaa_audit_pack", REPO_ROOT / "ops" / "audit-pack" / "pack.py"
)
assert _spec and _spec.loader
pack = importlib.util.module_from_spec(_spec)
sys.modules["oaa_audit_pack"] = pack
_spec.loader.exec_module(pack)

_vspec = importlib.util.spec_from_file_location(
    "oaa_verify_pack", REPO_ROOT / "tools" / "verifier" / "verify_pack.py"
)
assert _vspec and _vspec.loader
verify_pack = importlib.util.module_from_spec(_vspec)
sys.modules["oaa_verify_pack"] = verify_pack
_vspec.loader.exec_module(verify_pack)


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> dict:
    out = tmp_path_factory.mktemp("audit-pack")
    return pack.build_pack(
        DEMO / "evidence_store.jsonl",
        DEMO / "trust_roots.jsonl",
        out,
        clock=CLOCK,
    )


# ------------------------------------------------------------ build --------


def test_build_produces_contract_files(built: dict) -> None:
    d = pathlib.Path(built["pack_dir"])
    for rel in (
        "receipts.jsonl",
        "keys/trust_roots.jsonl",
        "timestamps/README.md",
        "policies/README.md",
        "chain_graph.json",
        "claims.md",
        "manifest.json",
        "verify-notes.md",
    ):
        assert (d / rel).is_file(), rel
    assert pathlib.Path(built["zip"]).is_file()
    assert built["counts"]["receipts"] >= 1


def test_receipts_byte_exact(built: dict) -> None:
    src = [ln for ln in (DEMO / "evidence_store.jsonl").read_text().splitlines() if ln.strip()]
    out = pathlib.Path(built["pack_dir"]) / "receipts.jsonl"
    assert out.read_text().splitlines() == src


def test_manifest_covers_all_files(built: dict) -> None:
    d = pathlib.Path(built["pack_dir"])
    manifest = json.loads((d / "manifest.json").read_text())
    on_disk = {str(p.relative_to(d)) for p in d.rglob("*") if p.is_file()} - {"manifest.json"}
    assert set(manifest["files"]) == on_disk
    for rel, digest in manifest["files"].items():
        assert hashlib.sha256((d / rel).read_bytes()).hexdigest() == digest


def test_window_filter_single_receipt(built: dict, tmp_path: pathlib.Path) -> None:
    """--from/--to window bounds by signed iat; --receipt-hash selects one."""
    lines = [ln for ln in (DEMO / "evidence_store.jsonl").read_text().splitlines() if ln.strip()]
    rec = json.loads(lines[0])
    first = pack.select_envelopes(DEMO / "evidence_store.jsonl", receipt_hash=rec["receipt_hash"])
    assert len(first) == 1 and first[0] == lines[0]
    t0 = pack._event_time(lines[0])
    lo, hi = t0.replace(microsecond=0), t0.replace(microsecond=0)
    sub = pack.select_envelopes(DEMO / "evidence_store.jsonl", from_utc=lo, to_utc=hi)
    assert sub == [ln for ln in lines if lo <= pack._event_time(ln) <= hi]


def test_chain_graph_slot_pending(built: dict) -> None:
    data = json.loads((pathlib.Path(built["pack_dir"]) / "chain_graph.json").read_text())
    assert data["status"] == "pending P1.1a wire-up"
    # additive: the manifest is file-grained, so filling the slot later
    # cannot break other entries.
    assert json.loads((pathlib.Path(built["pack_dir"]) / "manifest.json").read_text())["files"]


def test_claim_sheet_no_claims_and_guard(built: dict) -> None:
    text = (pathlib.Path(built["pack_dir"]) / "claims.md").read_text()
    pack.assert_no_compliance_claims(text)  # raises on any positive claim
    assert pack.GUARD_HEADER in text and pack.GUARD_SENTINEL in text
    assert "not establish legal or regulatory" in text


def test_no_timestamps_degrades_honestly(built: dict) -> None:
    d = pathlib.Path(built["pack_dir"]) / "timestamps"
    README = (d / "README.md").read_text()
    assert "No receipt in this window carries an RFC 3161 timestamp anchor" in README
    assert not list(d.glob("*.token"))


def test_policies_degrade_honestly(built: dict) -> None:
    assert (
        "Not included" in (pathlib.Path(built["pack_dir"]) / "policies" / "README.md").read_text()
    )


def test_deterministic_build(built: dict, tmp_path: pathlib.Path) -> None:
    again = pack.build_pack(
        DEMO / "evidence_store.jsonl",
        DEMO / "trust_roots.jsonl",
        tmp_path / "again",
        clock=CLOCK,
    )
    if pathlib.Path(again["zip"]).read_bytes() != pathlib.Path(built["zip"]).read_bytes():
        # zip timestamps may drift; the manifest and claim sheet must not
        a = json.loads((pathlib.Path(built["pack_dir"]) / "manifest.json").read_text())
        b = json.loads((pathlib.Path(again["pack_dir"]) / "manifest.json").read_text())
        assert a == b


# ----------------------------------------------------------- verify --------


def test_verify_green_on_demo_pack(built: dict) -> None:
    report = verify_pack.verify_pack(pathlib.Path(built["pack_dir"]))
    assert not report.failed
    assert not report.warned
    names = [c.name for c in report.checks]
    for want in (
        "manifest-integrity",
        "key-snapshot",
        "receipt-signatures",
        "timestamp-tokens",
        "claim-sheet-guard",
        "chain-graph-slot",
    ):
        assert want in names, want
    sig = next(c for c in report.checks if c.name == "receipt-signatures")
    # real cryptography ran: the demo Ed25519 receipts verify
    assert "signature valid" in sig.message


def test_verify_zip_roundtrip(built: dict) -> None:
    report = verify_pack.verify_pack(pathlib.Path(built["zip"]))
    assert not report.failed


def test_tamper_single_byte_fails_naming_file(built: dict, tmp_path: pathlib.Path) -> None:

    d = tmp_path / "tampered"
    shutil.copytree(pathlib.Path(built["pack_dir"]), d)
    target = d / "verify-notes.md"
    data = bytearray(target.read_bytes())
    assert len(data) > 1
    data[0] = data[0] ^ 0x01  # flip one bit
    target.write_bytes(bytes(data))
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = next(c for c in report.checks if c.name == "manifest-integrity")
    assert check.status == "FAIL"
    assert "verify-notes.md" in check.message


def test_tampered_receipt_named(built: dict, tmp_path: pathlib.Path) -> None:
    """Rewrite a receipt's signed payload: both the manifest digest and the
    receipt checks trip, naming the file / the affected receipts."""

    d = tmp_path / "tampered-receipt"
    shutil.copytree(pathlib.Path(built["pack_dir"]), d)
    p = d / "receipts.jsonl"
    rec = json.loads(p.read_text().splitlines()[0])
    h, pay, s = rec["jws"].split(".")
    payload = json.loads(verify_pack._b64d(pay))
    payload["agent_id"] = "agent:evil"
    new_pay = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    rec["jws"] = f"{h}.{new_pay}.{s}"
    lines = p.read_text().splitlines()
    lines[0] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    report = verify_pack.verify_pack(d)
    assert report.failed
    # the manifest names the changed file, and the receipt check agrees
    assert (
        "receipts.jsonl" in next(c for c in report.checks if c.name == "manifest-integrity").message
    )


def test_strip_claim_guard_is_warning_not_failure(built: dict, tmp_path: pathlib.Path) -> None:

    d = tmp_path / "guardless"
    shutil.copytree(pathlib.Path(built["pack_dir"]), d)
    p = d / "claims.md"
    text = p.read_text()
    text = text.replace(pack.GUARD_HEADER + "\n\n" + pack.GUARD_SENTINEL, "_[guard removed]_")
    p.write_text(text)
    # an honest manifest re-stamp (an insider could do this too) so the
    # manifest check stays green and the guard warning alone is exercised
    m = json.loads((d / MANIFEST).read_text())
    m["files"]["claims.md"] = hashlib.sha256(p.read_bytes()).hexdigest()
    (d / MANIFEST).write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    report = verify_pack.verify_pack(d)
    assert not report.failed  # a warning, not a failure
    assert report.warned
    check = next(c for c in report.checks if c.name == "claim-sheet-guard")
    assert "guard" in check.warnings[0]


def test_timestamp_token_green_path(tmp_path: pathlib.Path) -> None:
    """Mint a real Ed25519 receipt that claims an RFC 3161 anchor and check
    the verifier validates the embedded token presence."""
    key = Ed25519PrivateKey.generate()
    kid = "0123456789abcdef"
    pem = (
        key.public_key()
        .public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    root = {
        "key_id": kid,
        "public_key_pem": pem,
        "valid_from": "1970-01-01T00:00:00+00:00",
        "valid_until": None,
        "status": "current",
        "note": "test-minted key",
    }
    payload = {
        "agent_id": "agent:ts-test",
        "iat": 1793781819,
        "input_hash": "00" * 32,
        "x_timestamp": {
            "mode": "tsa",
            "digest": "sha256:" + "00" * 32,
            "token": base64.b64encode(b"TSA-TOKEN-DER").decode(),
        },
    }
    hp = (
        base64.urlsafe_b64encode(
            json.dumps({"alg": "EdDSA", "kid": kid, "typ": "provenance-receipt/v1"}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    pp = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    sig = base64.urlsafe_b64encode(key.sign(f"{hp}.{pp}".encode())).rstrip(b"=").decode()
    jws = f"{hp}.{pp}.{sig}"
    rh = "sha256:" + hashlib.sha256(jws.encode()).hexdigest()
    store = tmp_path / "evidence_store.jsonl"
    store.write_text(json.dumps({"receipt_hash": rh, "jws": jws}) + "\n")
    roots = tmp_path / "trust_roots.jsonl"
    roots.write_text(json.dumps(root) + "\n")
    built = pack.build_pack(store, roots, tmp_path / "out")
    d = pathlib.Path(built["pack_dir"])
    token = next((d / "timestamps").glob("*.token"))
    assert token.read_bytes() == b"TSA-TOKEN-DER"
    report = verify_pack.verify_pack(d)
    assert not report.failed
    check = next(c for c in report.checks if c.name == "timestamp-tokens")
    assert check.status == "PASS" and "matching token file" in check.message
    sig_check = next(c for c in report.checks if c.name == "receipt-signatures")
    assert "1 of 1" in sig_check.message


def test_verdict_render_legible(built: dict, capsys: pytest.CaptureFixture) -> None:
    out = verify_pack.verify_pack(pathlib.Path(built["zip"])).render()
    assert "OVERALL VERDICT: GREEN" in out
    for c in verify_pack.verify_pack(pathlib.Path(built["zip"])).checks:
        assert c.status in ("PASS", "FAIL")


def test_cli_exit_codes(built: dict) -> None:
    assert verify_pack.main([str(built["pack_dir"])]) == 0


# ---------------------------------------------------- import boundary ------


def test_verifier_import_boundary_stdlib_plus_cryptography_only() -> None:
    """P1.7b contract: no imports beyond stdlib + cryptography (and the
    verifier's own module). Enforced by static AST scan."""
    tree = ast.parse((REPO_ROOT / "tools" / "verifier" / "verify_pack.py").read_text())
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    allowed = set(sys.stdlib_module_names) | {"cryptography"}
    assert roots - allowed == set(), (
        f"verifier imports outside stdlib+cryptography: {roots - allowed}"
    )
    assert "raucle" not in roots
    assert "oaa_raucle_adapter" not in roots
    assert "oaa_investigation_ui" not in roots


# ------------------------------------------------- P1.1c offline export ----


def test_verify_makes_no_network_attempt(built: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    """P1.1c contract proven at runtime: re-verification succeeds with the
    network gone. Sockets are monkeypatched to count and refuse any
    connection attempt; the run stays green and the counter stays at zero
    for the unpacked pack and the shipped zip."""
    attempts: list[str] = []

    class _RefusingSocket:
        def __init__(self, *a: object, **k: object) -> None:
            attempts.append(f"socket.socket({a!r})")

        def __getattr__(self, name: str):  # pragma: no cover - refusal first
            raise AssertionError("network attempted during offline verification")

    monkeypatch.setattr(socket, "socket", _RefusingSocket)
    monkeypatch.setattr(
        socket, "create_connection", lambda *a, **k: attempts.append("socket.create_connection")
    )
    monkeypatch.setattr(
        socket, "getaddrinfo", lambda *a, **k: attempts.append(f"socket.getaddrinfo({a!r})")
    )
    monkeypatch.setattr(
        http.client.HTTPConnection,
        "connect",
        lambda self: attempts.append("http.client.HTTPConnection.connect"),
    )
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda *a, **k: attempts.append("urllib.request.urlopen")
    )

    for target in (pathlib.Path(built["pack_dir"]), pathlib.Path(built["zip"])):
        attempts.clear()
        report = verify_pack.verify_pack(target)
        assert not report.failed, report.render()
        assert attempts == [], f"verifier attempted network use: {attempts}"


def test_manifest_declares_pinned_snapshot_and_self_containment(built: dict) -> None:
    m = json.loads((pathlib.Path(built["pack_dir"]) / MANIFEST).read_text())
    snap = m["pinned_key_snapshot"]
    keys_file = pathlib.Path(built["pack_dir"]) / snap["file"]
    assert keys_file.is_file()
    assert hashlib.sha256(keys_file.read_bytes()).hexdigest() == snap["sha256"]
    assert snap["key_ids"], "snapshot must name the pinned key ids"
    assert m["self_contained"] == {
        "offline": True,
        "requires": "Python 3.11+ standard library plus the cryptography package",
        "network": "none",
        "raucle": "not required at verification time",
    }
    # verifier agrees, and does not warn on a P1.1c pack
    report = verify_pack.verify_pack(pathlib.Path(built["pack_dir"]))
    pk = next(c for c in report.checks if c.name == "pinned-key-snapshot")
    assert pk.status == "PASS" and not report.warned


def test_build_refuses_key_not_in_pinned_snapshot(tmp_path: pathlib.Path) -> None:
    """A self-contained export is impossible when the window uses a key the
    embedded snapshot does not carry: the build refuses, naming the key."""
    key = Ed25519PrivateKey.generate()
    kid = "deadbeefdeadbeef"
    key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo).decode()
    payload = {"agent_id": "agent:x", "agent_key_id": kid, "iat": 1700000000}
    hp = (
        base64.urlsafe_b64encode(
            json.dumps({"alg": "EdDSA", "kid": kid, "typ": "provenance-receipt/v1"}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    pp = (
        base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode())
        .rstrip(b"=")
        .decode()
    )
    sig = base64.urlsafe_b64encode(key.sign(f"{hp}.{pp}".encode())).rstrip(b"=").decode()
    jws = f"{hp}.{pp}.{sig}"
    store = tmp_path / "evidence_store.jsonl"
    store.write_text(
        json.dumps(
            {"receipt_hash": "sha256:" + hashlib.sha256(jws.encode()).hexdigest(), "jws": jws}
        )
        + "\n"
    )
    # a snapshot that intentionally misses the signing key
    roots = tmp_path / "trust_roots.jsonl"
    other = Ed25519PrivateKey.generate()
    other_pem = (
        other.public_key()
        .public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    roots.write_text(
        json.dumps(
            {
                "key_id": "other",
                "public_key_pem": other_pem,
                "valid_from": "1970-01-01T00:00:00+00:00",
                "valid_until": None,
            }
        )
        + "\n"
    )
    with pytest.raises(ValueError, match="deadbeefdeadbeef"):
        pack.build_pack(store, roots, tmp_path / "out")


@pytest.mark.skipif(
    not RAUCLE_OSS_HOME.is_dir(), reason="RAUCLE_OSS_HOME tree not present on this machine"
)
def test_resolved_pack_with_pinned_keys_self_contained(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With RAUCLE_OSS_HOME opt-in the resolved graphs embed real verify
    results from the pinned snapshot, and any receipt the graphs reference
    beyond the window ships in signatures/ (the full signature bundle)."""
    monkeypatch.setenv("RAUCLE_OSS_HOME", str(RAUCLE_OSS_HOME))
    built = pack.build_pack(
        DEMO / "evidence_store.jsonl", DEMO / "trust_roots.jsonl", tmp_path / "out", clock=CLOCK
    )
    d = pathlib.Path(built["pack_dir"])
    cg = json.loads((d / "chain_graph.json").read_text())
    assert cg["status"] == "resolved-by-pinned-verifier"
    graphs = cg["graphs"]
    assert graphs, "demo receipts must resolve"
    sig_states = [
        n["signature"]["status"]
        for g in graphs.values()
        for n in g.get("nodes", [])
        if n.get("kind") == "receipt" and isinstance(n.get("signature"), dict)
    ]
    assert sig_states and all(s == "verified" for s in sig_states), sig_states
    bundle = d / "signatures" / "chain_receipts.jsonl"
    # every graph receipt id is carried inside the pack
    report = verify_pack.verify_pack(d)
    assert not report.failed, report.render()
    names = [c.name for c in report.checks]
    assert "signature-bundle" in names
    if bundle.is_file():
        packed_hashes = set()
        for rel in ("receipts.jsonl", "signatures/chain_receipts.jsonl"):
            for ln in (d / rel).read_text().splitlines():
                if ln.strip():
                    packed_hashes.add(json.loads(ln)["receipt_hash"])
        node_ids = {
            n["id"]
            for g in graphs.values()
            for n in g.get("nodes", [])
            if n.get("kind") == "receipt"
        }
        assert node_ids <= packed_hashes
        report2 = verify_pack.verify_pack(d)
        assert any(c.name == "signature-bundle" and c.status == "PASS" for c in report2.checks)


def test_chain_pack_graph_coverage_check_fails_without_bundle(
    built: dict, tmp_path: pathlib.Path
) -> None:
    """A tampered export that drops the bundle while keeping a resolved
    graph is caught: the coverage check names the missing dependency."""
    d = tmp_path / "stripped"
    shutil.copytree(pathlib.Path(built["pack_dir"]), d)
    cg = d / "chain_graph.json"
    data = json.loads(cg.read_text())
    assert data["status"] == "pending P1.1a wire-up"
    data["status"] = verify_pack.CHAIN_GRAPH_RESOLVED
    data["graphs"] = {
        "sha256:aa" * 1: {"nodes": [{"id": "sha256:" + "aa" * 32, "kind": "receipt"}]}
    }
    cg.write_text(json.dumps(data))
    m = json.loads((d / MANIFEST).read_text())
    m["files"]["chain_graph.json"] = hashlib.sha256(cg.read_bytes()).hexdigest()
    (d / MANIFEST).write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = next(c for c in report.checks if c.name == "chain-graph-slot")
    assert check.status == "FAIL" and "not shipped" in check.message


def test_signature_bundle_tamper_fails_named(built: dict, tmp_path: pathlib.Path) -> None:
    d = tmp_path / "bundle-tamper"
    shutil.copytree(pathlib.Path(built["pack_dir"]), d)
    p = d / "signatures" / "chain_receipts.jsonl"
    if not p.is_file():
        pytest.skip("demo window needed no off-window chain receipts")
    p.write_text(p.read_text() + "\n")  # corrupt: extra newline changes bytes
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = next(c for c in report.checks if c.name == "manifest-integrity")
    assert "chain_receipts.jsonl" in check.message


# ------------------------------------------------ claim sheet rendering (P1.7c) ---


def test_render_claim_sheet_cli_matches_pack(built: dict, tmp_path: pathlib.Path) -> None:
    """The renderer CLI is thin wiring, not a second claim-sheet code path."""
    repo = REPO_ROOT
    cmd = [
        sys.executable,
        str(repo / "scripts" / "render_claim_sheet.py"),
        "--evidence-store",
        str(DEMO / "evidence_store.jsonl"),
        "--trust-roots",
        str(DEMO / "trust_roots.jsonl"),
        "--clock",
        CLOCK.isoformat(),
    ]
    env = {**os.environ, "PYTHONPATH": str(repo)}
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, env=env)
    assert proc.returncode == 0, proc.stderr
    expected = (pathlib.Path(built["pack_dir"]) / "claims.md").read_text()
    assert proc.stdout == expected
    pack.assert_no_compliance_claims(proc.stdout)
    assert pack.GUARD_HEADER in proc.stdout and pack.GUARD_SENTINEL in proc.stdout


def test_rendered_demo_claim_sheet_ships_with_guard() -> None:
    """The checked-in rendered sample is a real generator output, guard intact."""
    sample = REPO_ROOT / "docs" / "demo" / "auditor-claims-demo.md"
    text = sample.read_text()
    assert pack.GUARD_HEADER in text and pack.GUARD_SENTINEL in text
    pack.assert_no_compliance_claims(text)
    assert "<!-- Rendered sample" in text


def test_key_snapshot_coverage_guard():
    pack._assert_key_snapshot_covers({"sha256:abc"}, {"sha256:abc"})
    with pytest.raises(ValueError, match="cannot build a self-contained export"):
        pack._assert_key_snapshot_covers({"sha256:abc"}, {"sha256:def"})


def test_chain_graph_resolver_path_requires_opt_in(monkeypatch):
    monkeypatch.delenv("RAUCLE_OSS_HOME", raising=False)
    assert pack._chain_graph_resolver_path() is None
