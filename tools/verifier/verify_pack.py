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
import json
import pathlib
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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


def load_pack(target: pathlib.Path) -> tuple[pathlib.Path, bool]:
    """Return (pack_dir, is_temp). Accepts a directory or a .zip."""
    target = pathlib.Path(target)
    if target.is_dir():
        return target, False
    if zipfile.is_zipfile(target):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="oaa-verify-"))
        with zipfile.ZipFile(target) as zf:
            zf.extractall(tmp)
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
    manifest = json.loads((pack / MANIFEST_NAME).read_text(encoding="utf-8"))
    files: dict[str, str] = manifest.get("files", {})
    problems: list[str] = []
    for rel, digest in sorted(files.items()):
        p = pack / rel
        if not p.is_file():
            problems.append(f"missing {rel} — the manifest promises it; the pack does not have it")
        elif _sha256_file(p) != digest:
            problems.append(f"{rel} — recorded sha256 {digest[:16]}… but the file hashes to {_sha256_file(p)[:16]}… (tampered after export)")
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
    for p in sorted((pack / "keys").glob("*.jsonl")):
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            kid = str(row.get("key_id"))
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
        pub = serialization.load_pem_public_key(
            pem.encode() if isinstance(pem, str) else pem
        )
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
    want = "sha256:" + hashlib.sha256(rec["jws"].encode()).hexdigest()
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
        return f"{label}: event at {event_time.isoformat()} falls outside key {kid!r} validity window"
    reason = _check_signature(rec["jws"], root["public_key_pem"])
    if reason:
        return f"{label}: {reason}"
    return None


def _envelope_files(pack: pathlib.Path) -> list[pathlib.Path]:
    """Every envelope file in the pack: receipts.jsonl plus the full
    signature bundle under signatures/."""
    files = [pack / "receipts.jsonl"]
    sig_dir = pack / "signatures"
    if sig_dir.is_dir():
        files += sorted(sig_dir.glob("*.jsonl"))
    return files


def check_signature_bundle(pack: pathlib.Path, report: Report, keys: dict[str, dict]) -> None:
    """Verify every bundle envelope beyond the query window (P1.1c):
    the chain receipts a resolved graph depends on must carry their own
    valid signatures inside the pack."""
    sig_dir = pack / "signatures"
    if not sig_dir.is_dir():
        return  # packs built before P1.1c carry no signatures/ directory
    bundle_files = sorted(sig_dir.glob("*.jsonl"))
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
        report.checks.append(Check("signature-bundle", "FAIL", f"{len(failures)} of {total} bundle receipt(s) FAILED: {'; '.join(failures)}"))
    else:
        report.checks.append(Check("signature-bundle", "PASS", f"{ok} of {total} chain receipt(s) in signatures/: receipt_hash re-derived, signature valid against the pinned snapshot."))


def check_receipts(pack: pathlib.Path, report: Report, keys: dict[str, dict], key_problems: list[str]) -> None:
    if key_problems or not (pack / "keys").is_dir():
        report.checks.append(Check("key-snapshot", "FAIL", "; ".join(key_problems) or "keys/ directory absent"))
        return
    report.checks.append(Check("key-snapshot", "PASS", f"{len(keys)} public key(s) in the embedded snapshot (public halves only)."))

    receipts_path = pack / "receipts.jsonl"
    lines = [ln for ln in receipts_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    failures = []
    ok_count = 0
    for i, line in enumerate(lines, 1):
        label = f"receipt {i}"
        try:
            rec = json.loads(line)
            header, payload_b64, _sig = rec["jws"].split(".")
            header_d = json.loads(_b64d(header))
            payload = json.loads(_b64d(payload_b64))
        except Exception as exc:
            failures.append(f"{label}: unreadable envelope ({exc})")
            continue
        want = "sha256:" + hashlib.sha256(rec["jws"].encode()).hexdigest()
        if rec["receipt_hash"] != want:
            failures.append(f"{label}: receipt_hash does not re-derive from the receipt bytes (tampered)")
            continue
        kid = header_d.get("kid")
        if kid not in keys:
            failures.append(f"{label}: signing key {kid!r} is not in the key snapshot — the pack cannot vouch for it")
            continue
        root = keys[kid]
        iat = int(payload.get("iat", 0))
        event_time = dt.datetime.fromtimestamp(iat, tz=dt.UTC)
        start = dt.datetime.fromisoformat(root["valid_from"])
        end = dt.datetime.fromisoformat(root["valid_until"]) if root.get("valid_until") else None
        if event_time < start or (end and event_time >= end):
            failures.append(f"{label}: event at {event_time.isoformat()} falls outside key {kid!r} validity window")
            continue
        reason = _check_signature(rec["jws"], root["public_key_pem"])
        if reason:
            failures.append(f"{label}: {reason}")
            continue
        ok_count += 1
    status, msg = (
        (
            "FAIL",
            f"{len(failures)} of {len(lines)} receipt(s) FAILED: {'; '.join(failures)}",
        )
        if failures
        else ("PASS", f"{ok_count} of {len(lines)} receipt(s): receipt_hash re-derived, signature valid against the key snapshot, event time within the key's validity window.")
    )
    report.checks.append(Check("receipt-signatures", status, msg))


def check_timestamps(pack: pathlib.Path, report: Report) -> None:
    ts_dir = pack / "timestamps"
    lines = [ln for ln in (pack / "receipts.jsonl").read_text(encoding="utf-8").splitlines() if ln.strip()]
    claimed: list[tuple[str, bytes]] = []
    for line in lines:
        payload = json.loads(_b64d(json.loads(line)["jws"].split(".")[1]))
        x_ts = payload.get("x_timestamp") if isinstance(payload, dict) else None
        if isinstance(x_ts, dict) and x_ts.get("token"):
            claimed.append((json.loads(line)["receipt_hash"], _b64d(str(x_ts["token"]))))
    failures = []
    for rh, token in claimed:
        p = ts_dir / f"{rh.replace(':', '-')}.token"
        if not p.is_file():
            failures.append(f"receipt {rh[:24]}… claims an RFC 3161 anchor but its token file is missing from timestamps/")
        elif p.read_bytes() != token:
            failures.append(f"receipt {rh[:24]}…: token file does not match the token embedded in the receipt (tampered)")
    if failures:
        report.checks.append(Check("timestamp-tokens", "FAIL", "; ".join(failures)))
    elif claimed:
        report.checks.append(Check("timestamp-tokens", "PASS", f"{len(claimed)} claimed RFC 3161 anchor(s) carried matching token file(s)."))
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
                warnings=["the pack has no claim sheet at all — ask the operator to regenerate the pack with one"],
            )
        )
        return
    text = p.read_text(encoding="utf-8")
    missing = [name for name, needle in (("guard section", GUARD_HEADER), ("guard sentence", GUARD_SENTINEL)) if needle not in text]
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


def check_chain_graph(pack: pathlib.Path, report: Report) -> None:
    p = pack / "chain_graph.json"
    if not p.is_file():
        report.checks.append(Check("chain-graph-slot", "PASS", "chain_graph.json absent — the slot is additive and its absence is noted, not concealed."))
        return
    data = json.loads(p.read_text(encoding="utf-8"))
    status = data.get("status", "")
    # P1.1c self-containment: every receipt a RESOLVED graph depends on
    # must be shipped inside the pack (receipts.jsonl or signatures/).
    if status == CHAIN_GRAPH_RESOLVED:
        shipped: set[str] = set()
        for path in _envelope_files(pack):
            if path.is_file():
                for ln in path.read_text(encoding="utf-8").splitlines():
                    if ln.strip():
                        try:
                            shipped.add(json.loads(ln)["receipt_hash"])
                        except Exception as exc:
                            report.checks.append(Check("chain-graph-slot", "FAIL", f"undecodable envelope in {path.name}: {exc}"))
                            return
        holes: list[str] = []
        for rh, g in data.get("graphs", {}).items():
            if isinstance(g, dict) and g.get("status") == "unresolved":
                continue
            for node in (g or {}).get("nodes", []):
                if isinstance(node, dict) and node.get("kind") == "receipt":
                    rid = node.get("id", "")
                    if rid.startswith("sha256:") and rid not in shipped:
                        holes.append(f"{rh[:24]}… depends on {rid[:24]}… which is not shipped in the pack")
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
    block = json.loads(m.read_text(encoding="utf-8")).get("pinned_key_snapshot")
    if not block:
        report.checks.append(
            Check(
                "pinned-key-snapshot",
                "PASS",
                "Pack carries no pinned-key-snapshot manifest block (pre-P1.1c layout); receipt checks still ran against keys/.",
                warnings=["this pack does not declare a pinned key snapshot digest; ask the operator for a P1.1c export"],
            )
        )
        return
    rel = block.get("file", "")
    f = pack / rel
    if not f.is_file():
        report.checks.append(Check("pinned-key-snapshot", "FAIL", f"declared snapshot {rel!r} is missing from the pack"))
    elif _sha256_file(f) != block.get("sha256"):
        report.checks.append(Check("pinned-key-snapshot", "FAIL", f"declared snapshot digest for {rel!r} does not match the embedded bytes"))
    else:
        report.checks.append(Check("pinned-key-snapshot", "PASS", f"The declared pinned key snapshot {rel} matches its recorded digest ({len(block.get('key_ids', []))} key id(s)); verification depends on nothing outside the pack."))


# ----------------------------------------------------------------- CLI -----


def verify_pack(target: pathlib.Path) -> Report:
    pack, is_temp = load_pack(target)
    try:
        report = Report()
        if not (pack / MANIFEST_NAME).is_file():
            report.checks.append(Check("manifest-integrity", "FAIL", "manifest.json missing — the pack cannot verify itself"))
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
