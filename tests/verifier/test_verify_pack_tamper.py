# SPDX-License-Identifier: Apache-2.0
"""AUD-01 verifier tamper classes: a genuine pack verifies clean, and every
tamper class fails VISIBLY, naming the artifact.

This is the 'prove it to my auditor' tool. Each test here is one LASR demo
claim: an auditor's-eye attack against a shipped pack must produce a RED
verdict whose message names what was tampered — swapped receipt hash,
rogue-key re-sign, missing key grant (snapshot absent / key not pinned /
event outside the key's validity grant), unreadable envelopes, zip-slip
members, damaged manifests, stripped timestamp anchors, stripped claim
guard, and damaged chain-graph/pinned-snapshot sections.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import json
import pathlib
import sys
import zipfile

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import generate_private_key

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

_vspec = importlib.util.spec_from_file_location(
    "oaa_verify_pack_tamper", REPO_ROOT / "tools" / "verifier" / "verify_pack.py"
)
assert _vspec
assert _vspec.loader
verify_pack = importlib.util.module_from_spec(_vspec)
sys.modules.setdefault("oaa_verify_pack_tamper", verify_pack)
_vspec.loader.exec_module(verify_pack)


# ------------------------------------------------------------ mint helpers ----

CLOCK_IAT = int(dt.datetime(2026, 11, 5, 12, 0, 0, tzinfo=dt.UTC).timestamp())


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def mint_envelope(
    *,
    kid: str = "0123456789abcdef",
    payload: dict | None = None,
    with_timestamp: bool = False,
    iat: int = CLOCK_IAT,
) -> tuple[dict, str]:
    """Mint a real Ed25519 receipt plus its matching trust-root row."""
    key = Ed25519PrivateKey.generate()
    pem = (
        key.public_key()
        .public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    row = {
        "key_id": kid,
        "public_key_pem": pem,
        "valid_from": "1970-01-01T00:00:00+00:00",
        "valid_until": None,
        "status": "current",
        "note": "tamper-class test key",
    }
    body = {"agent_id": "agent:tamper-class", "iat": iat}
    if payload:
        body.update(payload)
    if with_timestamp:
        body["x_timestamp"] = {
            "mode": "tsa",
            "digest": "sha256:" + "00" * 32,
            "token": base64.b64encode(b"TSA-TOKEN-DER").decode(),
        }
    hp = (
        base64.urlsafe_b64encode(
            json.dumps({"alg": "EdDSA", "kid": kid, "typ": "provenance-receipt/v1"}).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    pp = (
        base64.urlsafe_b64encode(json.dumps(body, separators=(",", ":"), sort_keys=True).encode())
        .rstrip(b"=")
        .decode()
    )
    sig = base64.urlsafe_b64encode(key.sign(f"{hp}.{pp}".encode())).rstrip(b"=").decode()
    jws = f"{hp}.{pp}.{sig}"
    line = json.dumps(
        {"receipt_hash": "sha256:" + hashlib.sha256(jws.encode()).hexdigest(), "jws": jws}
    )
    return row, line


def write_manifest(d: pathlib.Path) -> None:
    files = {
        str(p.relative_to(d)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(d.rglob("*"))
        if p.is_file() and p.name != MANIFEST
    }
    m = {
        "pack": "AUD-01 auditor export pack",
        "pinned_key_snapshot": {
            "file": "keys/trust_roots.jsonl",
            "sha256": hashlib.sha256((d / "keys" / "trust_roots.jsonl").read_bytes()).hexdigest(),
            "key_ids": ["0123456789abcdef"],
            "note": "verbatim pinned snapshot",
        },
        "files": files,
    }
    (d / MANIFEST).write_text(json.dumps(m, indent=2, sort_keys=True) + "\n")


def restamp_manifest(d: pathlib.Path) -> None:
    """Re-stamp manifest digests from the on-disk bytes (an insider could do
    this; every test using it proves the check that trips is deeper than
    the manifest alone)."""
    write_manifest(d)


MANIFEST = "manifest.json"
RECEIPTS = "receipts.jsonl"


def _pack(
    tmp_path: pathlib.Path,
    *,
    mint=None,
    roots: list[dict] | None = None,
    receipts: list[str] | None = None,
) -> pathlib.Path:
    """A minimal, well-formed, self-contained pack with one real Ed25519 receipt."""
    mint = mint or mint_envelope
    d = tmp_path / "pack"
    d.mkdir()
    root_row, line = mint()
    (d / RECEIPTS).write_text("\n".join(receipts if receipts is not None else [line]) + "\n")
    (d / "keys").mkdir()
    rows = roots if roots is not None else [root_row]
    (d / "keys" / "trust_roots.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
    )
    write_manifest(d)
    return d


# ----------------------------------------------------------- clean baseline ----


def test_genuine_pack_verifies_clean(tmp_path: pathlib.Path) -> None:
    """Baseline: a genuine, self-contained pack is GREEN with every core
    check PASS (the absence warning below is the claim sheet's honest
    absence notice, asserted explicitly as non-fatal)."""
    d = _pack(tmp_path)
    report = verify_pack.verify_pack(d)
    assert not report.failed, report.render()
    assert "OVERALL VERDICT: AMBER" in report.render()  # claims.md absent only
    for name in ("manifest-integrity", "key-snapshot", "receipt-signatures"):
        assert next(c for c in report.checks if c.name == name).status == "PASS"


def test_main_exit_code_red_on_tamper(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    (d / RECEIPTS).write_text("not json\n")
    restamp_manifest(d)
    assert verify_pack.main([str(d)]) == 1


def test_manifest_missing_fails_the_pack(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    (d / MANIFEST).unlink()
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = report.checks[0]
    assert check.name == "manifest-integrity"
    assert "manifest.json missing" in check.message


def test_manifest_unreadable_json_fails(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    (d / MANIFEST).write_text("{broken")
    report = verify_pack.verify_pack(d)
    assert report.failed
    assert (
        "not readable JSON"
        in next(c for c in report.checks if c.name == "manifest-integrity").message
    )
    assert (
        "not readable JSON"
        in next(c for c in report.checks if c.name == "pinned-key-snapshot").message
    )


def test_extra_undeclared_file_fails_manifest(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    (d / "smuggled.json").write_text("{}")
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = next(c for c in report.checks if c.name == "manifest-integrity")
    assert "smuggled.json" in check.message
    assert "not covered by the manifest" in check.message


def test_missing_pinned_snapshot_file_fails_manifest_and_key_check(
    tmp_path: pathlib.Path,
) -> None:
    d = _pack(tmp_path)
    (d / "keys" / "trust_roots.jsonl").unlink()
    report = verify_pack.verify_pack(d)
    assert report.failed
    assert (
        "keys/trust_roots.jsonl"
        in next(c for c in report.checks if c.name == "manifest-integrity").message
    )
    assert (
        "key snapshot is empty"
        in next(c for c in report.checks if c.name == "key-snapshot").message
    )


# ------------------------------------------------------- receipt tamper classes ----


def test_swapped_receipt_hash_fails_visibly(tmp_path: pathlib.Path) -> None:
    """LASR claim: a receipt whose recorded hash no longer re-derives from
    its bytes is RED, and the failure names that receipt line."""
    d = _pack(tmp_path)
    p = d / RECEIPTS
    rec = json.loads(p.read_text().splitlines()[0])
    rec["receipt_hash"] = "sha256:" + "ab" * 32  # swapped in a bogus hash
    p.write_text(json.dumps(rec) + "\n")
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed, report.render()
    check = next(c for c in report.checks if c.name == "receipt-signatures")
    assert check.status == "FAIL"
    assert "receipt_hash does not re-derive" in check.message
    assert "receipt 1" in check.message


def test_rogue_key_resign_fails_not_in_snapshot(tmp_path: pathlib.Path) -> None:
    """LASR claim: re-signing a receipt with an attacker key that the pinned
    snapshot does not carry cannot smuggle it past the verifier."""
    rogue = mint_envelope(kid="ee000000000000ee", payload={"agent_id": "agent:rogue"})
    d = _pack(tmp_path, receipts=[rogue[1]])
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed, report.render()
    check = next(c for c in report.checks if c.name == "receipt-signatures")
    assert "not in the key snapshot" in check.message


def test_missing_key_snapshot_dir_fails(tmp_path: pathlib.Path) -> None:
    import shutil  # noqa: PLC0415 - only this test mutates the key tree

    d = _pack(tmp_path)
    restamp_manifest(d)  # stamp while the snapshot is still on disk
    shutil.rmtree(d / "keys")
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = next(c for c in report.checks if c.name == "key-snapshot")
    assert check.status == "FAIL"
    assert "key snapshot is empty" in check.message
    # the removed snapshot is also caught at manifest and pin level
    assert report.failed
    assert (
        "keys/trust_roots.jsonl"
        in next(c for c in report.checks if c.name == "manifest-integrity").message
    )


def test_empty_key_snapshot_fails(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path, roots=[])
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    assert (
        "key snapshot is empty"
        in next(c for c in report.checks if c.name == "key-snapshot").message
    )


def test_duplicate_and_unreadable_key_rows_fail(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    keys = d / "keys" / "trust_roots.jsonl"
    rows = [json.loads(ln) for ln in keys.read_text().splitlines() if ln.strip()]
    keys.write_text(json.dumps(rows[0]) + "\njson{bad\n" + json.dumps(rows[0]) + "\n")
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    msg = next(c for c in report.checks if c.name == "key-snapshot").message
    assert "unreadable row" in msg
    assert "duplicate key_id" in msg


def test_event_outside_key_validity_grant_fails(tmp_path: pathlib.Path) -> None:
    """LASR claim: an event time outside the signing key's stated validity
    grant is RED, even though the signature itself is real."""
    row, line = mint_envelope()
    row["valid_from"] = "2099-01-01T00:00:00+00:00"
    d = _pack(tmp_path, mint=lambda: (row, line))
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = next(c for c in report.checks if c.name == "receipt-signatures")
    assert "falls outside key" in check.message
    assert "validity window" in check.message


def test_unreadable_envelope_line_fails_named(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path, receipts=["{not-an-envelope"])
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = next(c for c in report.checks if c.name == "receipt-signatures")
    assert "unreadable envelope" in check.message
    assert "receipt 1" in check.message


def test_envelope_missing_fields_fails_cleanly(tmp_path: pathlib.Path) -> None:
    _row, line = mint_envelope()
    rec = json.loads(line)
    rec = {"jws": rec["jws"]}  # hash field stripped, envelope kept
    d = _pack(tmp_path, receipts=[json.dumps(rec)])
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    assert (
        "malformed envelope, missing envelope fields"
        in next(c for c in report.checks if c.name == "receipt-signatures").message
    )


def test_non_eddsa_algorithm_is_refused(tmp_path: pathlib.Path) -> None:
    """A receipt re-signed with a different JWS algorithm is refused, not
    silently accepted: this verifier checks EdDSA receipts only."""
    _row, line = mint_envelope()
    rec = json.loads(line)
    h, pay, _old_sig = rec["jws"].split(".")
    header = json.loads(_b64d(h))
    header["alg"] = "ES256"
    nh = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    jws = f"{nh}.{pay}.{_old_sig}"
    rec = {
        "receipt_hash": "sha256:" + hashlib.sha256(jws.encode()).hexdigest(),
        "jws": jws,
    }
    d = _pack(tmp_path, receipts=[json.dumps(rec, sort_keys=True)])
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = next(c for c in report.checks if c.name == "receipt-signatures")
    assert "unsupported signature algorithm" in check.message
    assert "this verifier checks EdDSA receipts only" in check.message


def test_signature_verify_failure_against_pinned_key_fails(tmp_path: pathlib.Path) -> None:
    """Key IS pinned but signature bytes are forged: RED with the honest
    'signature does not verify' reason (crypto actually ran)."""
    row, line = mint_envelope()
    rec = json.loads(line)
    h, pay, sig = rec["jws"].split(".")
    forged = list(sig)
    forged[0] = "A" if forged[0] != "A" else "B"
    jws = f"{h}.{pay}.{''.join(forged)}"
    rec = {
        "receipt_hash": "sha256:" + hashlib.sha256(jws.encode()).hexdigest(),
        "jws": jws,
    }
    d = _pack(tmp_path, mint=lambda: (row, json.dumps(rec, sort_keys=True)))
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    assert (
        "signature does not verify against the key snapshot"
        in next(c for c in report.checks if c.name == "receipt-signatures").message
    )


def test_non_ed25519_snapshot_key_is_refused(tmp_path: pathlib.Path) -> None:
    row, line = mint_envelope()
    rsa = generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa.public_key().public_bytes(ser.Encoding.PEM, ser.PublicFormat.SubjectPublicKeyInfo)
    row["public_key_pem"] = pem.decode()
    d = _pack(tmp_path, mint=lambda: (row, line))
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    msg = next(c for c in report.checks if c.name == "receipt-signatures").message
    assert "not an Ed25519 public key" in msg


# ------------------------------------------------------------ timestamps ----


def test_claimed_anchor_without_token_file_fails(tmp_path: pathlib.Path) -> None:
    row, line = mint_envelope(with_timestamp=True)
    d = _pack(tmp_path, mint=lambda: (row, line))  # no timestamps/ dir written
    (d / "timestamps").mkdir()
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = next(c for c in report.checks if c.name == "timestamp-tokens")
    assert "token file is missing" in check.message


def test_timestamp_token_bytes_mismatch_fails(tmp_path: pathlib.Path) -> None:
    """The claimed RFC 3161 anchor exists but its token bytes were swapped:
    the verifier names the tampered anchor, it does not pass on presence."""
    row, line = mint_envelope(with_timestamp=True)
    d = _pack(tmp_path, mint=lambda: (row, line))
    rec = json.loads((d / RECEIPTS).read_text().splitlines()[0])
    (d / "timestamps").mkdir()
    fn = rec["receipt_hash"].replace(":", "-") + ".token"
    (d / "timestamps" / fn).write_bytes(b"TAMPERED-TOKEN")
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed, report.render()
    check = next(c for c in report.checks if c.name == "timestamp-tokens")
    assert "does not match the token embedded" in check.message


def test_no_claimed_anchor_is_stated_scope_not_failure(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    report = verify_pack.verify_pack(d)
    check = next(c for c in report.checks if c.name == "timestamp-tokens")
    assert check.status == "PASS"
    assert "nothing to check" in check.message


# ------------------------------------------------------------ claim sheet ----


def test_absent_claim_sheet_warns_not_fails(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    report = verify_pack.verify_pack(d)
    assert not report.failed
    assert report.warned
    check = next(c for c in report.checks if c.name == "claim-sheet-guard")
    assert "no claim sheet at all" in check.warnings[0]


# ---------------------------------------------------------- zip handling ----


def test_pack_target_missing_fails_loudly(tmp_path: pathlib.Path) -> None:
    with pytest.raises(SystemExit, match="not a zip/directory"):
        verify_pack.load_pack(tmp_path / "nope")


def test_zip_slip_member_is_refused(tmp_path: pathlib.Path) -> None:
    """LASR claim: the verifier never trusts the pack it verifies — a
    zip-slip member is refused before any byte is written."""
    z = tmp_path / "pack.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("../escape.json", "{}")
    with pytest.raises(SystemExit, match="unsafe entry"):
        verify_pack.verify_pack(z)


def test_non_regular_zip_member_is_refused(tmp_path: pathlib.Path) -> None:
    z = tmp_path / "pack.zip"
    with zipfile.ZipFile(z, "w") as zf:
        info = zipfile.ZipInfo("receipts.jsonl/")
        info.external_attr = (0o040755 << 16) | 0x10  # directory flag
        zf.writestr(info, "")
    with pytest.raises(SystemExit, match="non-regular entry"):
        verify_pack.verify_pack(z)


def test_wrapperless_zip_with_lone_keys_subdir_is_normalised(tmp_path: pathlib.Path) -> None:
    """A zip without the audit-pack/ wrapper whose only subdirectory is
    keys/ used to be misread as pack-rooted-at-keys; the loader now
    normalises and the genuine pack verifies GREEN."""
    row, line = mint_envelope()
    z = tmp_path / "flat.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr(RECEIPTS, line + "\n")
        zf.writestr("keys/trust_roots.jsonl", json.dumps(row) + "\n")
        zf.writestr(
            MANIFEST,
            json.dumps(
                {
                    "pack": "AUD-01",
                    "pinned_key_snapshot": {
                        "file": "keys/trust_roots.jsonl",
                        "sha256": hashlib.sha256((json.dumps(row) + "\n").encode()).hexdigest(),
                        "key_ids": [row["key_id"]],
                        "note": "n",
                    },
                    "files": {
                        RECEIPTS: hashlib.sha256((line + "\n").encode()).hexdigest(),
                        "keys/trust_roots.jsonl": hashlib.sha256(
                            (json.dumps(row) + "\n").encode()
                        ).hexdigest(),
                    },
                },
                sort_keys=True,
            ),
        )
    report = verify_pack.verify_pack(z)
    assert not report.failed, report.render()


def test_zip_roundtrip_of_genuine_pack_stays_green(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    z = tmp_path / "genuine.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for p in sorted(d.rglob("*")):
            if p.is_file():
                zf.write(p, str(p.relative_to(d)))
    report = verify_pack.verify_pack(z)
    assert not report.failed, report.render()


# ------------------------------------------------- signature bundle paths ----


def test_bundle_rogue_signature_fails_named(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    _rogue_row, rogue_line = mint_envelope(kid="ee00000000000001")
    sig_dir = d / "signatures"
    sig_dir.mkdir()
    (sig_dir / "chain_receipts.jsonl").write_text(rogue_line + "\n")
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = next(c for c in report.checks if c.name == "signature-bundle")
    assert check.status == "FAIL"
    assert "not in the key snapshot" in check.message


def test_bundle_directory_declares_none_needed(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    (d / "signatures").mkdir()
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert not report.failed
    check = next(c for c in report.checks if c.name == "signature-bundle")
    assert "states this rather than implying a gap" in check.message


def test_bundle_valid_chain_receipts_pass_with_count(tmp_path: pathlib.Path) -> None:
    row, line = mint_envelope()
    d = _pack(tmp_path, mint=lambda: (row, line))
    sig_dir = d / "signatures"
    sig_dir.mkdir()
    (sig_dir / "chain_receipts.jsonl").write_text(line + "\n")
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert not report.failed
    check = next(c for c in report.checks if c.name == "signature-bundle")
    assert "receipt_hash re-derived" in check.message
    assert "1 of 1" in check.message


def test_shipped_set_undecodable_envelope_fails_chain_graph_check(
    tmp_path: pathlib.Path,
) -> None:
    """A resolved graph forces the shipped-receipt set to be built; an
    undecodable envelope there is a FAIL, not a silent subset."""
    data = {"status": "resolved-by-pinned-verifier", "graphs": {}}
    d = _pack(tmp_path)
    cg = d / "chain_graph.json"
    cg.write_text(json.dumps(data))
    (d / RECEIPTS).write_text("garbage\n")
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    check = next(c for c in report.checks if c.name == "chain-graph-slot")
    assert "undecodable envelope" in check.message


# ------------------------------------------------------------ chain graph ----


def test_unreadable_chain_graph_fails(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    (d / "chain_graph.json").write_text("{oops")
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert report.failed
    assert (
        "not readable JSON"
        in next(c for c in report.checks if c.name == "chain-graph-slot").message
    )


def test_chain_graph_other_status_is_reported_not_faked(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    (d / "chain_graph.json").write_text(json.dumps({"status": "resolver-degraded"}))
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert not report.failed
    check = next(c for c in report.checks if c.name == "chain-graph-slot")
    assert "resolver-degraded" in check.message


def test_resolved_graph_with_shipped_dependencies_is_green(tmp_path: pathlib.Path) -> None:
    row, line = mint_envelope()
    d = _pack(tmp_path, mint=lambda: (row, line))
    rec = json.loads(line)
    (d / "chain_graph.json").write_text(
        json.dumps(
            {
                "status": "resolved-by-pinned-verifier",
                "graphs": {
                    rec["receipt_hash"]: {
                        "nodes": [
                            {"id": rec["receipt_hash"], "kind": "receipt"},
                            {"id": "policy:x", "kind": "policy"},
                        ]
                    }
                },
            }
        )
    )
    restamp_manifest(d)
    report = verify_pack.verify_pack(d)
    assert not report.failed, report.render()


# ----------------------------------------------------- pinned key snapshot ----


def test_pinned_snapshot_file_missing_fails(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    m = json.loads((d / MANIFEST).read_text())
    m["pinned_key_snapshot"] = {"file": "keys/gone.jsonl", "sha256": "x", "key_ids": []}
    (d / MANIFEST).write_text(json.dumps(m, sort_keys=True))
    report = verify_pack.verify_pack(d)
    assert report.failed
    assert (
        "declared snapshot 'keys/gone.jsonl' is missing"
        in next(c for c in report.checks if c.name == "pinned-key-snapshot").message
    )


def test_pinned_snapshot_digest_mismatch_fails(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    m = json.loads((d / MANIFEST).read_text())
    m["pinned_key_snapshot"] = {
        "file": "keys/trust_roots.jsonl",
        "sha256": "sha256:" + "00" * 32,
        "key_ids": ["k"],
    }
    (d / MANIFEST).write_text(json.dumps(m, sort_keys=True))
    report = verify_pack.verify_pack(d)
    assert report.failed
    assert (
        "does not match the embedded bytes"
        in next(c for c in report.checks if c.name == "pinned-key-snapshot").message
    )


def test_pre_p1_1c_pack_without_pinned_block_warns_honestly(tmp_path: pathlib.Path) -> None:
    """A pack that does not declare a pinned snapshot is verifiable against
    keys/ but states the gap — it is never claimed self-contained."""
    d = _pack(tmp_path)
    m = json.loads((d / MANIFEST).read_text())
    del m["pinned_key_snapshot"]
    (d / MANIFEST).write_text(json.dumps(m, sort_keys=True))
    report = verify_pack.verify_pack(d)
    assert not report.failed
    assert report.warned
    check = next(c for c in report.checks if c.name == "pinned-key-snapshot")
    assert "does not declare a pinned key snapshot" in check.warnings[0]


def test_no_pinned_block_and_no_manifest_is_only_manifest_failure(
    tmp_path: pathlib.Path,
) -> None:
    d = _pack(tmp_path)
    (d / MANIFEST).unlink()
    report = verify_pack.verify_pack(d)
    assert [c.name for c in report.checks if c.name == "pinned-key-snapshot"] == []


# ------------------------------------------------------- verdict rendering ----


def test_red_verdict_tells_the_auditor_not_to_rely_on_it(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    (d / RECEIPTS).write_text("garbage\n")
    restamp_manifest(d)
    out = verify_pack.verify_pack(d).render()
    assert "OVERALL VERDICT: RED" in out
    assert "do not rely on it" in out
    assert "receipt-signatures" in out


def test_amber_verdict_when_only_warnings(tmp_path: pathlib.Path) -> None:
    d = _pack(tmp_path)
    report = verify_pack.verify_pack(d)  # no claims.md -> warning only
    assert not report.failed
    assert report.warned
    assert "OVERALL VERDICT: AMBER" in report.render()
