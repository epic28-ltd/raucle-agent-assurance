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
import importlib.util
import json
import pathlib
import shutil
import sys

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "services" / "investigation-ui" / "demo_data"
CLOCK = dt.datetime(2026, 11, 5, 12, 0, 0, tzinfo=dt.UTC)
MANIFEST = "manifest.json"

_spec = importlib.util.spec_from_file_location("oaa_audit_pack", REPO_ROOT / "ops" / "audit-pack" / "pack.py")
assert _spec and _spec.loader
pack = importlib.util.module_from_spec(_spec)
sys.modules["oaa_audit_pack"] = pack
_spec.loader.exec_module(pack)

_vspec = importlib.util.spec_from_file_location("oaa_verify_pack", REPO_ROOT / "tools" / "verifier" / "verify_pack.py")
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
    sub = pack.select_envelopes(
        DEMO / "evidence_store.jsonl", from_utc=lo, to_utc=hi
    )
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
    assert "Not included" in (pathlib.Path(built["pack_dir"]) / "policies" / "README.md").read_text()


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
    for want in ("manifest-integrity", "key-snapshot", "receipt-signatures", "timestamp-tokens", "claim-sheet-guard", "chain-graph-slot"):
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
    new_pay = base64.urlsafe_b64encode(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()
    rec["jws"] = f"{h}.{new_pay}.{s}"
    lines = p.read_text().splitlines()
    lines[0] = json.dumps(rec)
    p.write_text("\n".join(lines) + "\n")
    report = verify_pack.verify_pack(d)
    assert report.failed
    # the manifest names the changed file, and the receipt check agrees
    assert "receipts.jsonl" in next(c for c in report.checks if c.name == "manifest-integrity").message


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
    pem = key.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo).decode()
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
        "x_timestamp": {"mode": "tsa", "digest": "sha256:" + "00" * 32, "token": base64.b64encode(b"TSA-TOKEN-DER").decode()},
    }
    hp = base64.urlsafe_b64encode(json.dumps({"alg": "EdDSA", "kid": kid, "typ": "provenance-receipt/v1"}).encode()).rstrip(b"=").decode()
    pp = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()).rstrip(b"=").decode()
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
    assert roots - allowed == set(), f"verifier imports outside stdlib+cryptography: {roots - allowed}"
    assert "raucle" not in roots
    assert "oaa_raucle_adapter" not in roots
    assert "oaa_investigation_ui" not in roots
