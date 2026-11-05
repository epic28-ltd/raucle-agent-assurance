# SPDX-License-Identifier: Apache-2.0
"""Open Agent Assurance — AUD-01 standalone pack verifier (P1.7b).

Deliberately standalone: this script may import only the Python standard
library and `cryptography`. No raucle, no project imports, no network.
An import-linter test (tests/audit-pack) enforces that boundary.

Usage:

    python verify_pack.py <pack-dir | pack.zip>

Checks, each reported PASS/FAIL/WARNING with a plain-English line:

1. Manifest integrity — every file named in manifest.json exists and its
   sha256 matches; every file present is named in the manifest.
2. Receipts — for each envelope: receipt_hash re-derives from the JWS
   bytes, and the Ed25519 signature validates against the embedded key
   snapshot within the key's stated validity window.
3. Timestamps — receipts claiming an RFC 3161 anchor carry a matching
   token in timestamps/ (byte-identical to the embedded DER).
4. Claim-sheet guard — claims.md must carry the mandatory no-claim guard;
   its absence is a WARNING (printed prominently, does not fail the run).
5. Reserved slot — chain_graph.json status is reported.

Overall verdict legible to a non-engineer; exit 0 green, 1 red.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import http.client
import json
import pathlib
import shutil
import socket
import tempfile
import urllib.request
import zipfile
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RECEIPTS_JSONL = "receipts.jsonl"
JSONL_GLOB = "*.jsonl"
SHA256_PREFIX = "sha256:"

GUARD_HEADER = "## Mandatory no-claim guard"
GUARD_SENTINEL = (
    "This pack records what was cryptographically observed inside a"
    " deliberately narrow scope. It does not establish legal or regulatory"
    " compliance, and it asserts no certification, no approval, no"
    " accreditation, no attestation, and no warranty of any kind."
)
CHAIN_GRAPH_PENDING = "pending P1.1a wire-up"
CHAIN_GRAPH_RESOLVED = "resolved-by-pinned-verifier"
MANIFEST_NAME = "manifest.json"
EXCLUDED = {MANIFEST_NAME}  # not hashed by itself (would be circular)


@dataclass
class Check:
    name: str
    status: str  # "PASS" | "FAIL"
    message: str
    warnings: list[str] = field(default_factory=list)


@dataclass
class Report:
    checks: list[Check] = field(default_factory=list)

    @property
    def failed(self) -> bool:
        return any(c.status == "FAIL" for c in self.checks)

    @property
    def warned(self) -> bool:
        return any(_warned(c) for c in self.checks)

    def render(self) -> str:
        lines = []
        for c in self.checks:
            lines.append(f"[{c.status}] {c.name}")
            lines.append(f"    {c.message}")
            for w in c.warnings:
                if w:
                    lines.append(f"    WARNING: {w}")
        if self.failed:
            verdict = "RED — verification failed. The pack above is not trustworthy as shipped; do not rely on it until the named failures are explained by the operator."
        elif self.warned:
            verdict = "AMBER — everything cryptographic verified, but warnings above were raised. Ask the operator to explain each one."
        else:
            verdict = "GREEN — the pack matches its manifest, and every receipt in it verified against the key snapshot."
        lines += ["", "OVERALL VERDICT: " + verdict]
        return "\n".join(lines) + "\n"


def _warned(c: Check) -> bool:
    return bool(c.warnings)


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _extract_zip_safely(zf: zipfile.ZipFile, dest: pathlib.Path) -> None:
    """Zip-slip-safe extraction: every member is validated before any write.

    A verifier must never trust the pack it is verifying: member names are
    rejected when absolute, dotted-up, or otherwise aiming outside the
    extraction root, and non-regular members (links, specials) are refused
    outright.
    """
    dest_r = dest.resolve()
    for m in zf.infolist():
        parts = pathlib.PurePosixPath(m.filename).parts
        if (
            not parts
            or pathlib.PurePosixPath(m.filename).is_absolute()
            or any(part in {"..", "."} for part in parts)
            or any("\\" in part or part.endswith(":") for part in parts)
        ):
            raise SystemExit(
                f"refusing to extract a pack containing an unsafe entry: {m.filename!r}"
            )
        if (m.external_attr >> 16) & 0o170000 not in (0, 0o100000):  # not a regular file
            raise SystemExit(
                f"refusing to extract a pack containing a non-regular entry: {m.filename!r}"
            )
        target = dest_r.joinpath(*parts)
        if dest_r != target and dest_r not in target.resolve().parents:
            raise SystemExit(
                f"refusing to extract {m.filename!r}: it would land outside the extraction root"
            )
        zf.extract(m, dest_r)


def load_pack(target: pathlib.Path) -> tuple[pathlib.Path, bool]:
    """Return (pack_dir, is_temp). Accepts a directory or a .zip."""
    target = pathlib.Path(target)
    if target.is_dir():
        return target, False
    if zipfile.is_zipfile(target):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="oaa-verify-"))  # mode 0700, private
        with zipfile.ZipFile(target) as zf:
            _extract_zip_safely(zf, tmp)
        subdirs = [d for d in tmp.iterdir() if d.is_dir()]
        pack_path = subdirs[0] if len(subdirs) == 1 else tmp
        # never hand out pack==tmp: the caller cleanup rmtree(pack.parent)
        # would otherwise delete the extraction root's parent
        if len(subdirs) != 1:
            inner = tmp / "audit-pack"
            inner.mkdir(exist_ok=True)
            for p in tmp.iterdir():
                if p != inner:
                    shutil.move(str(p), str(inner / p.name))
            pack_path = inner
        return pack_path, True
    raise SystemExit(f"pack target not found or not a zip/directory: {target}")


def check_manifest(pack: pathlib.Path, report: Report) -> None:
    try:
        manifest = json.loads((pack / MANIFEST_NAME).read_text(encoding="utf-8"))
        files: dict[str, str] = manifest.get("files", {})
    except Exception as exc:
        report.checks.append(
            Check(
                "manifest-integrity",
                "FAIL",
                f"manifest.json is not readable JSON ({exc}) — the pack's inventory is damaged",
            )
        )
        return
    problems: list[str] = []
    for rel, digest in sorted(files.items()):
        p = pack / rel
        if not p.is_file():
            problems.append(f"missing {rel} — the manifest promises it; the pack does not have it")
        elif _sha256_file(p) != digest:
            problems.append(
                f"{rel} — recorded sha256 {digest[:16]}… but the file hashes to {_sha256_file(p)[:16]}… (tampered after export)"
            )
    extra = sorted(
        str(p.relative_to(pack))
        for p in pack.rglob("*")
        if p.is_file() and str(p.relative_to(pack)) not in files and p.name != MANIFEST_NAME
    )
    if extra:
        problems.append("file(s) present but not covered by the manifest: " + ", ".join(extra))
    status, msg = (
        ("FAIL", f"manifest integrity FAILED for: {'; '.join(problems)}")
        if problems
        else ("PASS", f"{len(files)} file(s) all match their recorded sha256 digests.")
    )
    report.checks.append(Check("manifest-integrity", status, msg))


def load_key_snapshot(pack: pathlib.Path) -> tuple[dict[str, dict], list[str]]:
    keys: dict[str, dict] = {}
    problems: list[str] = []
    for p in sorted((pack / "keys").glob(JSONL_GLOB)):
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                kid = str(row.get("key_id"))
            except Exception as exc:
                problems.append(f"unreadable row in {p.name}: {exc}")
                continue
            if kid in keys:
                problems.append(f"duplicate key_id {kid!r} in key snapshot")
            keys[kid] = row
    if not keys:
        problems.append("no keys/*.jsonl rows found — the key snapshot is empty")
    return keys, problems


def _check_signature(jws: str, pem: str) -> str | None:
    """Verify the JWS Ed25519 signature; return None if valid, else a reason."""
    header_b64, payload_b64, sig_b64 = jws.split(".")
    header = json.loads(_b64d(header_b64))
    payload = json.loads(_b64d(payload_b64))
    if header.get("alg") != "EdDSA":
        return f"unsupported signature algorithm {header.get('alg')!r} (this verifier checks EdDSA receipts only)"
    try:
        pub = serialization.load_pem_public_key(pem.encode() if isinstance(pem, str) else pem)
        if not isinstance(pub, Ed25519PublicKey):
            return f"key snapshot entry is {type(pub).__name__}, not an Ed25519 public key"
        pub.verify(_b64d(sig_b64), f"{header_b64}.{payload_b64}".encode())
    except Exception:
        return "signature does not verify against the key snapshot"
    _ = payload  # decoded by caller
    return None


def _verify_one_envelope(line: str, label: str, keys: dict[str, dict]) -> str | None:
    """Per-envelope offline checks; return a failure reason or None."""
    try:
        rec = json.loads(line)
        header, payload_b64, _sig = rec["jws"].split(".")
        header_d = json.loads(_b64d(header))
        payload = json.loads(_b64d(payload_b64))
    except Exception as exc:
        return f"{label}: unreadable envelope ({exc})"
    want = SHA256_PREFIX + hashlib.sha256(rec["jws"].encode()).hexdigest()
    if rec["receipt_hash"] != want:
        return f"{label}: receipt_hash does not re-derive from the receipt bytes (tampered)"
    kid = header_d.get("kid")
    if kid not in keys:
        return f"{label}: signing key {kid!r} is not in the key snapshot — the pack cannot vouch for it"
    root = keys[kid]
    iat = int(payload.get("iat", 0))
    event_time = dt.datetime.fromtimestamp(iat, tz=dt.UTC)
    start = dt.datetime.fromisoformat(root["valid_from"])
    end = dt.datetime.fromisoformat(root["valid_until"]) if root.get("valid_until") else None
    if event_time < start or (end and event_time >= end):
        return (
            f"{label}: event at {event_time.isoformat()} falls outside key {kid!r} validity window"
        )
    reason = _check_signature(rec["jws"], root["public_key_pem"])
    if reason:
        return f"{label}: {reason}"
    return None


def _envelope_files(pack: pathlib.Path) -> list[pathlib.Path]:
    """Every envelope file in the pack: receipts.jsonl plus the full
    signature bundle under signatures/."""
    files = [pack / RECEIPTS_JSONL]
    sig_dir = pack / "signatures"
    if sig_dir.is_dir():
        files += sorted(sig_dir.glob(JSONL_GLOB))
    return files


def check_signature_bundle(pack: pathlib.Path, report: Report, keys: dict[str, dict]) -> None:
    """Verify every bundle envelope beyond the query window (P1.1c):
    the chain receipts a resolved graph depends on must carry their own
    valid signatures inside the pack."""
    sig_dir = pack / "signatures"
    if not sig_dir.is_dir():
        return  # packs built before P1.1c carry no signatures/ directory
    bundle_files = sorted(sig_dir.glob(JSONL_GLOB))
    if not bundle_files:
        report.checks.append(
            Check(
                "signature-bundle",
                "PASS",
                "No chain receipts beyond the query window were needed; the bundle directory states this rather than implying a gap.",
            )
        )
        return
    total = ok = 0
    failures = []
    for path in bundle_files:
        for i, line in enumerate(
            (ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()), 1
        ):
            total += 1
            reason = _verify_one_envelope(line, f"{path.name} line {i}", keys)
            if reason:
                failures.append(reason)
            else:
                ok += 1
    if failures:
        report.checks.append(
            Check(
                "signature-bundle",
                "FAIL",
                f"{len(failures)} of {total} bundle receipt(s) FAILED: {'; '.join(failures)}",
            )
        )
    else:
        report.checks.append(
            Check(
                "signature-bundle",
                "PASS",
                f"{ok} of {total} chain receipt(s) in signatures/: receipt_hash re-derived, signature valid against the pinned snapshot.",
            )
        )


def _check_one_receipt(line: str, label: str, keys: dict[str, dict]) -> str | None:
    """Re-derive, key-snapshot-resolve and verify one receipt. Returns the
    failure text, or None when the receipt passes."""
    try:
        rec = json.loads(line)
        header, payload_b64, _sig = rec["jws"].split(".")
        header_d = json.loads(_b64d(header))
        payload = json.loads(_b64d(payload_b64))
    except Exception as exc:
        return f"{label}: unreadable envelope ({exc})"
    try:
        want = SHA256_PREFIX + hashlib.sha256(rec["jws"].encode()).hexdigest()
        if rec["receipt_hash"] != want:
            return f"{label}: receipt_hash does not re-derive from the receipt bytes (tampered)"
    except (KeyError, TypeError, AttributeError) as exc:
        return f"{label}: malformed envelope, missing envelope fields ({exc})"
    kid = header_d.get("kid")
    if kid not in keys:
        return f"{label}: signing key {kid!r} is not in the key snapshot — the pack cannot vouch for it"
    root = keys[kid]
    iat = int(payload.get("iat", 0))
    event_time = dt.datetime.fromtimestamp(iat, tz=dt.UTC)
    start = dt.datetime.fromisoformat(root["valid_from"])
    end = dt.datetime.fromisoformat(root["valid_until"]) if root.get("valid_until") else None
    if event_time < start or (end and event_time >= end):
        return (
            f"{label}: event at {event_time.isoformat()} falls outside key {kid!r} validity window"
        )
    reason = _check_signature(rec["jws"], root["public_key_pem"])
    if reason:
        return f"{label}: {reason}"
    return None


def check_receipts(
    pack: pathlib.Path, report: Report, keys: dict[str, dict], key_problems: list[str]
) -> None:
    if key_problems or not (pack / "keys").is_dir():
        report.checks.append(
            Check("key-snapshot", "FAIL", "; ".join(key_problems) or "keys/ directory absent")
        )
        return
    report.checks.append(
        Check(
            "key-snapshot",
            "PASS",
            f"{len(keys)} public key(s) in the embedded snapshot (public halves only).",
        )
    )

    receipts_path = pack / RECEIPTS_JSONL
    lines = [ln for ln in receipts_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    failures = []
    ok_count = 0
    for i, line in enumerate(lines, 1):
        failure = _check_one_receipt(line, f"receipt {i}", keys)
        failures.extend([failure] if failure else [])
        ok_count += 0 if failure else 1
    status, msg = (
        (
            "FAIL",
            f"{len(failures)} of {len(lines)} receipt(s) FAILED: {'; '.join(failures)}",
        )
        if failures
        else (
            "PASS",
            f"{ok_count} of {len(lines)} receipt(s): receipt_hash re-derived, signature valid against the key snapshot, event time within the key's validity window.",
        )
    )
    report.checks.append(Check("receipt-signatures", status, msg))


def _claimed_timestamp_tokens(lines: list[str]) -> list[tuple[str, bytes]]:
    """(receipt_hash, token bytes) pairs claimed via x_timestamp."""
    claimed: list[tuple[str, bytes]] = []
    for line in lines:
        try:
            rec = json.loads(line)
        except Exception:
            # the receipts check names undecodable lines; nothing to claim here
            continue
        try:
            payload = json.loads(_b64d(rec["jws"].split(".")[1]))
            x_ts = payload.get("x_timestamp") if isinstance(payload, dict) else None
            if isinstance(x_ts, dict) and x_ts.get("token"):
                claimed.append((rec["receipt_hash"], _b64d(str(x_ts["token"]))))
        except Exception:
            continue
    return claimed


def _timestamp_token_failures(claimed: list[tuple[str, bytes]], ts_dir: pathlib.Path) -> list[str]:
    """Receipts whose claimed anchor has no matching token file (tampered)."""
    failures: list[str] = []
    for rh, token in claimed:
        p = ts_dir / f"{rh.replace(':', '-')}.token"
        if not p.is_file():
            failures.append(
                f"receipt {rh[:24]}… claims an RFC 3161 anchor but its token file is missing from timestamps/"
            )
        elif p.read_bytes() != token:
            failures.append(
                f"receipt {rh[:24]}…: token file does not match the token embedded in the receipt (tampered)"
            )
    return failures


def check_timestamps(pack: pathlib.Path, report: Report) -> None:
    ts_dir = pack / "timestamps"
    lines = [
        ln for ln in (pack / RECEIPTS_JSONL).read_text(encoding="utf-8").splitlines() if ln.strip()
    ]
    claimed = _claimed_timestamp_tokens(lines)
    failures = _timestamp_token_failures(claimed, ts_dir)
    if failures:
        report.checks.append(Check("timestamp-tokens", "FAIL", "; ".join(failures)))
    elif claimed:
        report.checks.append(
            Check(
                "timestamp-tokens",
                "PASS",
                f"{len(claimed)} claimed RFC 3161 anchor(s) carried matching token file(s).",
            )
        )
    else:
        report.checks.append(
            Check(
                "timestamp-tokens",
                "PASS",
                "No receipt in this pack claims an RFC 3161 timestamp anchor, so there is nothing to check — this is the pack's stated scope, not a failure.",
            )
        )


def check_claim_sheet(pack: pathlib.Path, report: Report) -> None:
    p = pack / "claims.md"
    if not p.is_file():
        report.checks.append(
            Check(
                "claim-sheet-guard",
                "PASS",
                "claims.md absent.",
                warnings=[
                    "the pack has no claim sheet at all — ask the operator to regenerate the pack with one"
                ],
            )
        )
        return
    text = p.read_text(encoding="utf-8")
    missing = [
        name
        for name, needle in (("guard section", GUARD_HEADER), ("guard sentence", GUARD_SENTINEL))
        if needle not in text
    ]
    if missing:
        report.checks.append(
            Check(
                "claim-sheet-guard",
                "PASS",
                "claims.md present, but incomplete.",
                warnings=[
                    f"the claim sheet's {missing[0]} is missing — a pack whose claim sheet does not carry the no-claim guard must not be relied on for any conclusion"
                ],
            )
        )
    else:
        report.checks.append(
            Check(
                "claim-sheet-guard",
                "PASS",
                "The claim sheet carries its mandatory no-claim guard: it records what was observed and disclaims legal or regulatory conclusions.",
            )
        )


def _shipped_receipt_hashes(pack: pathlib.Path, report: Report) -> set[str] | None:
    """Every receipt_hash shipped in the pack's envelope files.

    Returns None (with a FAIL check recorded) on an undecodable envelope.
    """
    shipped: set[str] = set()
    for path in _envelope_files(pack):
        if not path.is_file():
            continue
        for ln in path.read_text(encoding="utf-8").splitlines():
            if not ln.strip():
                continue
            try:
                shipped.add(json.loads(ln)["receipt_hash"])
            except Exception as exc:
                report.checks.append(
                    Check(
                        "chain-graph-slot",
                        "FAIL",
                        f"undecodable envelope in {path.name}: {exc}",
                    )
                )
                return None
    return shipped


def _graph_receipt_ids(g: dict) -> list[str]:
    """sha256 receipt ids a chain graph depends on."""
    return [
        node.get("id", "")
        for node in (g or {}).get("nodes", [])
        if isinstance(node, dict) and node.get("kind") == "receipt"
    ]


def _chain_graph_holes(data: dict, shipped: set[str]) -> list[str]:
    """Receipts a graph depends on that the pack does not ship."""
    holes: list[str] = []
    for rh, g in data.get("graphs", {}).items():
        if isinstance(g, dict) and g.get("status") == "unresolved":
            continue
        for rid in _graph_receipt_ids(g):
            if rid.startswith(SHA256_PREFIX) and rid not in shipped:
                holes.append(f"{rh[:24]}… depends on {rid[:24]}… which is not shipped in the pack")
    return holes


def check_chain_graph(pack: pathlib.Path, report: Report) -> None:
    p = pack / "chain_graph.json"
    if not p.is_file():
        report.checks.append(
            Check(
                "chain-graph-slot",
                "PASS",
                "chain_graph.json absent — the slot is additive and its absence is noted, not concealed.",
            )
        )
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except Exception as exc:
        report.checks.append(
            Check(
                "chain-graph-slot",
                "FAIL",
                f"chain_graph.json is not readable JSON ({exc}) — damaged pack",
            )
        )
        return
    status = data.get("status", "")
    # P1.1c self-containment: every receipt a RESOLVED graph depends on
    # must be shipped inside the pack (receipts.jsonl or signatures/).
    if status == CHAIN_GRAPH_RESOLVED:
        shipped = _shipped_receipt_hashes(pack, report)
        if shipped is None:
            return
        holes = _chain_graph_holes(data, shipped)
        if holes:
            report.checks.append(Check("chain-graph-slot", "FAIL", "; ".join(holes[:5])))
            return
    msg = (
        f"Chain-graph slot is {status!r}: the pack ships without receipt-chain resolution; individual receipts fully verify, but the pack does not yet assert how chains connect."
        if status == CHAIN_GRAPH_PENDING
        else f"Chain-graph slot reports {status!r}."
    )
    report.checks.append(Check("chain-graph-slot", "PASS", msg))


def check_pinned_key_snapshot(pack: pathlib.Path, report: Report) -> None:
    """P1.1c: the manifest's pinned_key_snapshot digest must match the
    embedded snapshot bytes (pack self-containment is itself checked)."""
    m = pack / MANIFEST_NAME
    if not m.is_file():
        return  # already failed as manifest missing
    try:
        block = json.loads(m.read_text(encoding="utf-8")).get("pinned_key_snapshot")
    except Exception as exc:
        report.checks.append(
            Check(
                "pinned-key-snapshot",
                "FAIL",
                f"manifest.json is not readable JSON ({exc}) — the pinned-key-snapshot block cannot be checked",
            )
        )
        return
    if not block:
        report.checks.append(
            Check(
                "pinned-key-snapshot",
                "PASS",
                "Pack carries no pinned-key-snapshot manifest block (pre-P1.1c layout); receipt checks still ran against keys/.",
                warnings=[
                    "this pack does not declare a pinned key snapshot digest; ask the operator for a P1.1c export"
                ],
            )
        )
        return
    rel = block.get("file", "")
    f = pack / rel
    if not f.is_file():
        report.checks.append(
            Check(
                "pinned-key-snapshot", "FAIL", f"declared snapshot {rel!r} is missing from the pack"
            )
        )
    elif _sha256_file(f) != block.get("sha256"):
        report.checks.append(
            Check(
                "pinned-key-snapshot",
                "FAIL",
                f"declared snapshot digest for {rel!r} does not match the embedded bytes",
            )
        )
    else:
        report.checks.append(
            Check(
                "pinned-key-snapshot",
                "PASS",
                f"The declared pinned key snapshot {rel} matches its recorded digest ({len(block.get('key_ids', []))} key id(s)); verification depends on nothing outside the pack.",
            )
        )


# ----------------------------------------------------------------- CLI -----


def verify_pack(target: pathlib.Path) -> Report:
    pack, is_temp = load_pack(target)
    try:
        report = Report()
        if not (pack / MANIFEST_NAME).is_file():
            report.checks.append(
                Check(
                    "manifest-integrity",
                    "FAIL",
                    "manifest.json missing — the pack cannot verify itself",
                )
            )
            return report
        check_manifest(pack, report)
        keys, key_problems = load_key_snapshot(pack)
        check_receipts(pack, report, keys, key_problems)
        check_signature_bundle(pack, report, keys)
        check_timestamps(pack, report)
        check_claim_sheet(pack, report)
        check_chain_graph(pack, report)
        check_pinned_key_snapshot(pack, report)
    finally:
        if is_temp:
            shutil.rmtree(pack.parent, ignore_errors=True)
    return report


# -------------------------------------------- P1.1V mid-run plug-pull audit ----

EXTERNAL_CALL_AUDIT: list[str] = []


def install_offline_audit() -> list[str]:
    """P1.1V: instrument the verifier path so that ANY attempted external
    call fails the run loudly (OSError) instead of passing silently, and
    every attempt is recorded on EXTERNAL_CALL_AUDIT.

    Honest gap, stated plainly: this is same-kernel monkeypatch isolation
    inside one Python process, not a physically unplugged machine and not a
    separate network namespace. The physical plug-pull beat is the W8 live
    demo, which is out of scope here. subprocess/namespace isolation is
    exercised separately by the demo and tests where `unshare -n` is
    available on the machine.
    """

    def _refuse(where: str):
        def _hook(*args, **kwargs):
            EXTERNAL_CALL_AUDIT.append(where)
            raise OSError(
                f"P1.1V offline audit: external call refused at {where}; "
                "zero external calls are permitted in the verifier path"
            )

        return _hook

    class _RefusingSocket:
        def __init__(self, *a, **k):
            EXTERNAL_CALL_AUDIT.append("socket.socket")
            raise OSError(
                "P1.1V offline audit: socket creation refused "
                "(zero external calls permitted in the verifier path)"
            )

        def __getattr__(self, name):
            raise OSError(
                "P1.1V offline audit: socket use refused "
                "(zero external calls permitted in the verifier path)"
            )

    socket.socket = _RefusingSocket  # type: ignore[assignment,misc]
    socket.create_connection = _refuse("socket.create_connection")  # type: ignore[assignment]
    socket.getaddrinfo = _refuse("socket.getaddrinfo")  # type: ignore[assignment]
    http.client.HTTPConnection.connect = _refuse("http.client.HTTPConnection.connect")  # type: ignore[assignment]
    urllib.request.urlopen = _refuse("urllib.request.urlopen")  # type: ignore[assignment]
    return EXTERNAL_CALL_AUDIT


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="AUD-01 standalone offline pack verifier (stdlib + cryptography only)"
    )
    ap.add_argument("pack", help="pack directory or .zip")
    args = ap.parse_args(argv)
    report = verify_pack(pathlib.Path(args.pack))
    print(report.render())
    return 1 if report.failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
