# SPDX-License-Identifier: Apache-2.0
"""Every SEC finding family yields an exportable, receipted audit pack.

LASR-audit claim under test: whichever finding class the rules engine raises
(SEC-004 tool-success-after-deny, SEC-006 new privileged tool, SEC-008
credential content, SEC-009 gate-less privileged execution, SEC-010
credential-without-lease, SEC-011 identity anomaly), the pack builder can
produce a self-contained pack whose receipt carries that family's evidence,
and the standalone verifier calls it GREEN. Also exercises the pack builder's
honest-gap branches: undecodable store lines, unresolvable referenced chain
receipts, policy coverage states, and the CLI surface.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "services" / "investigation-ui" / "demo_data"
CLOCK = dt.datetime(2026, 11, 5, 12, 0, 0, tzinfo=dt.UTC)
MANIFEST = "manifest.json"

_spec = importlib.util.spec_from_file_location(
    "oaa_audit_pack", REPO_ROOT / "ops" / "audit-pack" / "pack.py"
)
assert _spec
assert _spec.loader
pack = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("oaa_audit_pack", pack)
_spec.loader.exec_module(pack)

_vspec = importlib.util.spec_from_file_location(
    "oaa_verify_pack_sec", REPO_ROOT / "tools" / "verifier" / "verify_pack.py"
)
assert _vspec
assert _vspec.loader
verify_pack = importlib.util.module_from_spec(_vspec)
sys.modules.setdefault("oaa_verify_pack_sec", verify_pack)
_vspec.loader.exec_module(verify_pack)

# The SEC finding families of services/rules (oaa_rules core), the classes an
# auditor's findings board draws from.
FAMILIES = {
    "SEC-004": "tool-side success after a correlated deny",
    "SEC-006": "new privileged tool appears for an agent release",
    "SEC-008": "credential / forbidden content detected in telemetry index",
    "SEC-009": "tool-side privileged execution with no corroborating gate receipt",
    "SEC-010": "credential consumed with no matching issued lease",
    "SEC-011": "producer identity anomaly - mid-chain credential/identity substitution",
}


def _mint_family_receipt(
    family_id: str, blurb: str, *, kid: str = "0123456789abcdef"
) -> tuple[dict, str]:
    """One real Ed25519 receipt whose decision names the finding family."""
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
        "note": f"SEC-family fixture key for {family_id}",
    }
    iat = int(CLOCK.timestamp())
    body = {
        "agent_id": "agent:sec-family-fixture",
        "iat": iat,
        "guardrail_verdict": "deny",
        "rule": family_id,
        "rule_label": blurb,
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
        {
            "receipt_hash": "sha256:" + hashlib.sha256(jws.encode()).hexdigest(),
            "jws": jws,
        }
    )
    return row, line


@pytest.mark.parametrize("family_id", sorted(FAMILIES))
def test_sec_family_yields_receipted_green_pack(family_id: str, tmp_path: pathlib.Path) -> None:
    """LASR claim: every finding class yields an exportable pack, receipted,
    verifying GREEN offline."""
    row, line = _mint_family_receipt(family_id, FAMILIES[family_id])
    store = tmp_path / "evidence_store.jsonl"
    store.write_text(line + "\n")
    roots = tmp_path / "trust_roots.jsonl"
    roots.write_text(json.dumps(row) + "\n")
    built = pack.build_pack(store, roots, tmp_path / "out", clock=CLOCK)
    d = pathlib.Path(built["pack_dir"])
    assert built["counts"]["receipts"] == 1
    # the finding family travels inside the signed receipt payload...
    payload = json.loads(base64.urlsafe_b64decode(json.loads(line)["jws"].split(".")[1] + "=="))
    assert payload["rule"] == family_id
    # ...and the claim sheet states the receipt window it exports
    claims = (d / "claims.md").read_text()
    assert "**1** receipt envelope(s)" in claims
    # and the offline verifier calls the family's pack GREEN
    report = verify_pack.verify_pack(d)
    assert not report.failed, report.render()
    sig = next(c for c in report.checks if c.name == "receipt-signatures")
    assert "1 of 1 receipt(s)" in sig.message
    assert "signature valid" in sig.message
    # the zip variant verifies equally
    assert not verify_pack.verify_pack(pathlib.Path(built["zip"])).failed


def test_sec_010_missing_lease_receipt_reads_honestly(tmp_path: pathlib.Path) -> None:
    """SEC-010 specifically: the receipt records the credential use; the pack
    states exactly the window it carries and does not claim the lease existed."""
    row, line = _mint_family_receipt("SEC-010", FAMILIES["SEC-010"])
    store = tmp_path / "evidence_store.jsonl"
    store.write_text(line + "\n")
    roots = tmp_path / "trust_roots.jsonl"
    roots.write_text(json.dumps(row) + "\n")
    built = pack.build_pack(store, roots, tmp_path / "out", clock=CLOCK)
    claims = (pathlib.Path(built["pack_dir"]) / "claims.md").read_text()
    assert "no certification" in claims  # no-claim guard intact
    assert "not establish legal or regulatory" in claims
    pack.assert_no_compliance_claims(claims)


def test_build_pack_out_dir_refuses_filesystem_root(tmp_path: pathlib.Path) -> None:
    row, line = _mint_family_receipt("SEC-004", FAMILIES["SEC-004"])
    store = tmp_path / "evidence_store.jsonl"
    store.write_text(line + "\n")
    roots = tmp_path / "trust_roots.jsonl"
    roots.write_text(json.dumps(row) + "\n")
    with pytest.raises(ValueError, match="would be removed wholesale"):
        pack.build_pack(store, roots, pathlib.Path("/"))


def test_single_receipt_build_names_the_receipt_window(tmp_path: pathlib.Path) -> None:
    row, line = _mint_family_receipt("SEC-011", FAMILIES["SEC-011"])
    store = tmp_path / "evidence_store.jsonl"
    store.write_text(line + "\n")
    roots = tmp_path / "trust_roots.jsonl"
    roots.write_text(json.dumps(row) + "\n")
    rec = json.loads(line)
    built = pack.build_pack(
        store, roots, tmp_path / "out", receipt_hash=rec["receipt_hash"], clock=CLOCK
    )
    assert built["window"]["from"] is None
    claims = (pathlib.Path(built["pack_dir"]) / "claims.md").read_text()
    assert f"single receipt {rec['receipt_hash']}" in claims


def test_select_envelopes_window_and_missing_receipt(
    tmp_path: pathlib.Path, capsys: pytest.CaptureFixture
) -> None:
    """Undecodable store lines are reported to stderr — never silently
    dropped or repaired; a named missing receipt raises honestly."""
    _row, line = _mint_family_receipt("SEC-006", FAMILIES["SEC-006"])
    clean = tmp_path / "store.jsonl"
    clean.write_text(line + "\n")
    rh = json.loads(line)["receipt_hash"]
    assert pack.select_envelopes(clean, receipt_hash=rh) == [line]
    with pytest.raises(FileNotFoundError, match="not in evidence store"):
        pack.select_envelopes(clean, receipt_hash="sha256:" + "ff" * 32)
    messy = tmp_path / "messy_store.jsonl"
    messy.write_text("{garbage\n" + line + "\n")
    out = pack.select_envelopes(
        messy, from_utc=CLOCK - dt.timedelta(hours=1), to_utc=CLOCK + dt.timedelta(hours=1)
    )
    assert out == [line]
    err = capsys.readouterr().err
    assert "skipped undecodable store line" in err


def test_bundle_states_referenced_receipt_absent(tmp_path: pathlib.Path) -> None:
    """A resolved graph referencing a receipt not in the store: the bundle
    says so rather than faking the receipt."""
    missing = "sha256:" + "aa" * 32
    store = tmp_path / "store.jsonl"
    store.write_text("")  # store exists but carries no receipt at all
    out_dir = tmp_path / "pack"
    out_dir.mkdir()
    extra, note = pack.build_signature_bundle(
        store,
        [],
        pack.CHAIN_GRAPH_RESOLVED,
        {"g": {"nodes": [{"id": missing, "kind": "receipt"}]}},
        out_dir,
    )
    assert extra == 0
    assert "absent from the evidence store" in note
    readme = " ".join((out_dir / "signatures" / "README.md").read_text().split())
    assert "stated here rather than papered over" in readme


def test_bundle_copies_off_window_chain_receipts(tmp_path: pathlib.Path) -> None:
    _row, line = _mint_family_receipt("SEC-004", FAMILIES["SEC-004"])
    store = tmp_path / "store.jsonl"
    rec = json.loads(line)
    store.write_text(line + "\n")
    out_dir = tmp_path / "pack"
    out_dir.mkdir()
    extra, note = pack.build_signature_bundle(
        store,
        [],  # empty window: the referenced receipt is off-window
        pack.CHAIN_GRAPH_RESOLVED,
        {"g": {"nodes": [{"id": rec["receipt_hash"], "kind": "receipt"}]}},
        out_dir,
    )
    assert extra == 1
    assert "beyond the query window" in note
    packed = (out_dir / "signatures" / "chain_receipts.jsonl").read_text()
    assert packed.strip() == line


def test_build_with_policies_and_deployment_receipts(tmp_path: pathlib.Path) -> None:
    """SEC-009 audit posture: policy files plus the deployment-chain receipts
    named by the gate audit land in the pack, and the claim sheet says both."""
    row, line = _mint_family_receipt("SEC-009", FAMILIES["SEC-009"])
    demo_store = (DEMO / "evidence_store.jsonl").read_text().splitlines()
    store = tmp_path / "evidence_store.jsonl"
    store.write_text(line + "\n" + "\n".join(demo_store) + "\n")
    # the snapshot must cover every in-window signer: ours + the demo key
    demo_rows = [ln for ln in (DEMO / "trust_roots.jsonl").read_text().splitlines() if ln.strip()]
    roots = tmp_path / "trust_roots.jsonl"
    roots.write_text("\n".join([json.dumps(row), *demo_rows]) + "\n")
    pol_dir = tmp_path / "policies-src"
    pol_dir.mkdir()
    (pol_dir / "baseline.yaml").write_text("rules: []\n")
    dep_receipt = json.loads(demo_store[0])
    built = pack.build_pack(
        store,
        roots,
        tmp_path / "out",
        policies_dir=pol_dir,
        policy_receipt_hashes=[dep_receipt["receipt_hash"]],
        clock=CLOCK,
    )
    d = pathlib.Path(built["pack_dir"])
    assert (d / "policies" / "baseline.yaml").is_file()
    chain = (d / "policies" / "deployment_chain_receipts.jsonl").read_text()
    assert dep_receipt["receipt_hash"] in chain
    claims = (d / "claims.md").read_text()
    assert "policy file(s) and deployment-chain receipts" in claims
    report = verify_pack.verify_pack(d)
    assert not report.failed, report.render()


def test_build_with_policies_but_no_deployment_receipts_states_gap(
    tmp_path: pathlib.Path,
) -> None:
    row, line = _mint_family_receipt("SEC-009", FAMILIES["SEC-009"])
    store = tmp_path / "evidence_store.jsonl"
    store.write_text(line + "\n")
    # the snapshot must cover every in-window signer: ours + the demo key
    demo_rows = [ln for ln in (DEMO / "trust_roots.jsonl").read_text().splitlines() if ln.strip()]
    roots = tmp_path / "trust_roots.jsonl"
    roots.write_text("\n".join([json.dumps(row), *demo_rows]) + "\n")
    pol_dir = tmp_path / "policies-src"
    pol_dir.mkdir()
    (pol_dir / "baseline.yaml").write_text("rules: []\n")
    built = pack.build_pack(store, roots, tmp_path / "out", policies_dir=pol_dir, clock=CLOCK)
    claims = (pathlib.Path(built["pack_dir"]) / "claims.md").read_text()
    assert "not accessible at pack time" in claims
    readme = (pathlib.Path(built["pack_dir"]) / "policies" / "README.md").read_text()
    assert "treated honestly as a gap" in readme


def test_deployment_receipt_hash_absent_from_store_is_skipped(tmp_path: pathlib.Path) -> None:
    """A deployment-chain receipt id that the store does not carry is left
    out of the chain file; the pack never fabricates the missing envelope."""
    row, line = _mint_family_receipt("SEC-009", FAMILIES["SEC-009"])
    store = tmp_path / "evidence_store.jsonl"
    store.write_text(line + "\n")
    roots = tmp_path / "trust_roots.jsonl"
    roots.write_text(json.dumps(row) + "\n")
    built = pack.build_pack(
        store, roots, tmp_path / "out", policy_receipt_hashes=["sha256:" + "ee" * 32], clock=CLOCK
    )
    d = pathlib.Path(built["pack_dir"])
    chain = (d / "policies" / "deployment_chain_receipts.jsonl").read_text()
    assert "ee" * 32 not in chain


def test_policies_dir_non_yaml_files_are_not_copied(tmp_path: pathlib.Path) -> None:
    row, line = _mint_family_receipt("SEC-009", FAMILIES["SEC-009"])
    store = tmp_path / "evidence_store.jsonl"
    store.write_text(line + "\n")
    # the snapshot must cover every in-window signer: ours + the demo key
    demo_rows = [ln for ln in (DEMO / "trust_roots.jsonl").read_text().splitlines() if ln.strip()]
    roots = tmp_path / "trust_roots.jsonl"
    roots.write_text("\n".join([json.dumps(row), *demo_rows]) + "\n")
    pol_dir = tmp_path / "policies-src"
    pol_dir.mkdir()
    (pol_dir / "notes.txt").write_text("not a policy")
    built = pack.build_pack(store, roots, tmp_path / "out", policies_dir=pol_dir, clock=CLOCK)
    d = pathlib.Path(built["pack_dir"])
    assert not (d / "policies" / "notes.txt").exists()


def test_resolve_chain_graph_failure_becomes_a_graph_state(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The wire-up is absent (no RAUCLE_OSS_HOME): the pack ships the pending
    slot, and a resolver that raises per receipt records the failure honestly."""

    class _Boom:
        def resolve_chain_graph(self, *_a, **_k):
            raise RuntimeError("resolver exploded")

    row, line = _mint_family_receipt("SEC-004", FAMILIES["SEC-004"])
    rec = json.loads(line)
    rows = [row]
    graphs = pack.resolve_chain_graphs([line], rows, _Boom())
    assert graphs[rec["receipt_hash"]]["status"] == "unresolved"
    assert graphs[rec["receipt_hash"]]["reason"] == "RuntimeError"


# ------------------------------------------------------------------ CLI ----


def test_cli_builds_the_family_pack(tmp_path: pathlib.Path, capsys) -> None:
    row, line = _mint_family_receipt("SEC-008", FAMILIES["SEC-008"])
    store = tmp_path / "evidence_store.jsonl"
    store.write_text(line + "\n")
    roots = tmp_path / "trust_roots.jsonl"
    roots.write_text(json.dumps(row) + "\n")
    out = tmp_path / "out"
    rc = pack.main(
        [
            "--evidence-store",
            str(store),
            "--trust-roots",
            str(roots),
            "--out",
            str(out),
            "--clock",
            CLOCK.isoformat(),
        ]
    )
    assert rc == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["counts"]["receipts"] == 1
    assert pathlib.Path(summary["pack_dir"]).is_dir()


def test_cli_input_path_honest_errors(tmp_path: pathlib.Path) -> None:
    with pytest.raises(FileNotFoundError, match="not a regular file"):
        pack._cli_input_path(str(tmp_path / "missing.jsonl"), "evidence-store")
    with pytest.raises(FileNotFoundError, match="not a regular file"):
        pack._cli_input_path(str(tmp_path), "trust-roots")  # a directory


def test_parse_utc_accepts_naive_and_zoned() -> None:
    assert pack._parse_utc("2026-11-05T12:00:00").tzinfo == dt.UTC
    assert pack._parse_utc("2026-11-05T12:00:00+02:00").utcoffset() == dt.timedelta(0)
