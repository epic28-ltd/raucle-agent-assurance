# SPDX-License-Identifier: Apache-2.0
"""P1.7V second-laptop auditor role-play: verification story, end to end.

Simulates the acceptance criterion verbatim: "Verification story: auditor
role-play on a second laptop, no network, pack verifies, signed claim
sheet produced."

The flow, in one function (:func:`run_second_laptop_role_play`):

1. Build a fresh real audit pack here, through the existing pack builder
   (ops/audit-pack/pack.py, honest-report generator intact).
2. Copy exactly what an auditor would receive (the pack and the standalone
   verifier CLI) into a throwaway directory treated as the "second laptop".
   Nothing else of this repository crosses over.
3. Run the verifier in that directory under ``unshare`` with a fresh
   network namespace, after first proving inside that same namespace that
   the network is genuinely gone (a real socket connect must fail).
   Loopback is dropped too: a netns of its own has no interfaces at all
   until one is created, which this never does.
4. Prove the deliberate-tamper FAIL path in the same network-denied
   namespace: byte-tamper a receipt file, expect RED.
5. Re-render the claim sheet from the raw inputs with
   scripts/render_claim_sheet.py (operator side, no-claim guard
   re-asserted), confirm it is byte-identical to the pack's claims.md, then
   have the "auditor" sign the verified claim sheet with a fresh ephemeral
   Ed25519 key held on the second laptop.
6. Leave role-play-notes.md in the second-laptop directory stating honestly
   what the simulation is and is not.

Honest limits of the simulation (also recorded in the notes file): it is
the same kernel and the same physical machine, not a second laptop; the
isolation is one network namespace per run, not a separate device; on
macOS or any host without ``unshare`` (rootless user namespaces disabled)
there is no equivalent cheap network namespace, so the run falls back to
direct execution and records plainly that the no-network property was not
namespace-proven. The verifier's zero-network behaviour itself is already
proven by monkeypatch assertions in tests/audit-pack/test_audit_pack.py;
this story adds the namespace-level proof on top.
"""

from __future__ import annotations

import base64
import datetime as dt
import importlib.util
import pathlib
import shutil
import subprocess
import sys

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "oaa_audit_pack", REPO_ROOT / "ops" / "audit-pack" / "pack.py"
)
assert _spec is not None and _spec.loader is not None
pack = importlib.util.module_from_spec(_spec)
sys.modules["oaa_audit_pack"] = pack
_spec.loader.exec_module(pack)


class RolePlayError(RuntimeError):
    """Raised when any step of the role-play fails its expectation."""


# ------------------------------------------------------------------ helpers


def _find_network_prefix() -> tuple[list[str] | None, str]:
    """Find an ``unshare`` invocation that truly denies network, or None.

    Tries ``unshare -n`` (needs real root) then ``unshare -rn`` (rootless
    user namespace mapping, works on ordinary accounts where kernel
    user namespaces allow it). Each candidate is proven with a live socket
    connect attempt inside the namespace: if that attempt does not fail,
    the candidate is rejected rather than trusted.
    """
    py_code = "import socket;s=socket.socket();s.settimeout(2);s.connect(('10.255.255.1',1))"
    for prefix in (["unshare", "-n"], ["unshare", "-rn"]):
        try:
            proc = subprocess.run(
                [*prefix, sys.executable, "-c", py_code],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        # Network unreachable or no route: exactly what the namespace owes
        # us. A success (exit 0) means the namespace did not isolate, so we
        # do not count it as network denial.
        if proc.returncode != 0 and "Errno 101" in (proc.stdout + proc.stderr):
            return prefix, (
                "netns via `" + " ".join(prefix) + "`; socket connect inside "
                "the namespace fails with network unreachable (Errno 101)"
            )
    if shutil.which("unshare"):
        return None, (
            "NONE: unshare exists but no invocation proved a network-denied "
            "namespace in this environment (unshare needs root for -n, or "
            "user namespaces disabled for -r); falls back to direct runs"
        )
    return None, (
        "NONE: `unshare` is not installed on this host (macOS has no "
        "equivalent); falls back to direct runs"
    )


def _run_offline(
    prefix: list[str] | None, cmd: list[str], timeout: int = 120
) -> subprocess.CompletedProcess[str]:
    full = [*(prefix or []), *cmd]
    return subprocess.run(full, capture_output=True, text=True, timeout=timeout)


# -------------------------------------------------------------------- flow


def run_second_laptop_role_play(
    work_dir: pathlib.Path,
    *,
    clock: dt.datetime | None = None,
    evidence_store: pathlib.Path | None = None,
    trust_roots: pathlib.Path | None = None,
) -> dict:
    """Run the full P1.7V role-play; return a summary dict of artefacts."""
    work_dir = work_dir.resolve()
    build_dir = work_dir / "build"
    laptop_dir = work_dir / "second-laptop"
    tamper_dir = work_dir / "tamper-check"
    if work_dir.exists():
        shutil.rmtree(work_dir)
    for d in (build_dir, laptop_dir, tamper_dir):
        d.mkdir(parents=True)

    # (1) Fresh real pack, existing builder, honest-report generator path.
    ev = (
        evidence_store
        or REPO_ROOT / "services" / "investigation-ui" / "demo_data" / "evidence_store.jsonl"
    )
    tr = (
        trust_roots
        or REPO_ROOT / "services" / "investigation-ui" / "demo_data" / "trust_roots.jsonl"
    )
    built = pack.build_pack(ev, tr, build_dir, clock=clock)
    src_pack = pathlib.Path(built["pack_dir"])
    claims_text = (src_pack / "claims.md").read_text(encoding="utf-8")

    # (2) The handover: only the pack and the verifier CLI cross over.
    laptop_pack = laptop_dir / src_pack.name
    shutil.copytree(src_pack, laptop_pack)
    shutil.copy2(REPO_ROOT / "tools" / "verifier" / "verify_pack.py", laptop_dir / "verify_pack.py")

    # (3) Prove the namespace denies network before trusting it.
    prefix, isolation_note = _find_network_prefix()
    net_probe = None
    if prefix is not None:
        probe = _run_offline(
            prefix,
            [
                sys.executable,
                "-c",
                "import urllib.request;urllib.request.urlopen('http://127.0.0.1:1',timeout=2)",
            ],
        )
        net_probe = {
            "command": "python urllib.urlopen in-namespace",
            "expectedly_failed": probe.returncode != 0,
            "detail": (probe.stderr or probe.stdout).strip(),
        }
        if not net_probe["expectedly_failed"]:
            raise RolePlayError(
                "network namespace did not deny network; refusing to continue as 'no network'"
            )

    green_run = _run_offline(
        prefix,
        [sys.executable, str(laptop_dir / "verify_pack.py"), str(laptop_pack)],
    )
    if green_run.returncode != 0 or "OVERALL VERDICT: GREEN" not in green_run.stdout:
        raise RolePlayError(
            f"offline verification did not come back green (exit {green_run.returncode}):\n{green_run.stdout}\n{green_run.stderr}"
        )
    (laptop_dir / "verification-green.txt").write_text(green_run.stdout, encoding="utf-8")

    # (4) Deliberate tamper, same network-denied namespace, expect RED.
    tampered_pack = tamper_dir / src_pack.name
    shutil.copytree(laptop_pack, tampered_pack)
    receipts = tampered_pack / "receipts.jsonl"
    receipts.write_bytes(
        receipts.read_bytes() + b"\n"
    )  # one byte class of change: fails the manifest
    tamper_run = _run_offline(
        prefix,
        [sys.executable, str(laptop_dir / "verify_pack.py"), str(tampered_pack)],
    )
    if tamper_run.returncode != 1 or "OVERALL VERDICT: RED" not in tamper_run.stdout:
        raise RolePlayError(
            f"deliberate tamper did not come back RED with exit 1 (exit {tamper_run.returncode}):\n{tamper_run.stdout}\n{tamper_run.stderr}"
        )
    if "RED" not in tamper_run.stdout:
        raise RolePlayError("tamper run must render a RED verdict line")
    (laptop_dir / "verification-tamper-RED.txt").write_text(tamper_run.stdout, encoding="utf-8")

    # (5) Claim sheet: re-render from raw inputs (operator side, repo CLI),
    cmd = [
        sys.executable,
        str(REPO_ROOT / "scripts" / "render_claim_sheet.py"),
        "--evidence-store",
        str(ev),
        "--trust-roots",
        str(tr),
    ]
    if clock is not None:
        cmd += ["--clock", clock.isoformat()]
    rendered = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if rendered.returncode != 0:
        raise RolePlayError(f"render_claim_sheet.py failed:\n{rendered.stderr}")
    # Byte-identical re-render requires the same clock the pack used. When
    # the caller pins a clock we pass it through; otherwise we derive it
    # from the pack's own "Generated:" line rather than the wall clock,
    # which would make every unpinned run flakily differ by microseconds.
    if clock is None:
        generated = next(
            (
                line.split("Generated: ", 1)[1].strip()
                for line in claims_text.splitlines()
                if line.startswith("Generated: ")
            ),
            None,
        )
        if generated is None:
            raise RolePlayError(
                "pack claims.md has no 'Generated:' line to pin the re-render clock"
            )
        cmd += ["--clock", generated]
    rendered = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    if rendered.returncode != 0:
        raise RolePlayError(f"render_claim_sheet.py failed:\n{rendered.stderr}")
    if rendered.stdout != claims_text:
        raise RolePlayError("re-rendered claim sheet differs from the pack's claims.md")
    pack.assert_no_compliance_claims(rendered.stdout)
    assert pack.GUARD_HEADER in rendered.stdout and pack.GUARD_SENTINEL in rendered.stdout
    (laptop_dir / "claims.md").write_text(rendered.stdout, encoding="utf-8")

    # Auditor signature: ephemeral Ed25519 key generated on the laptop itself,
    # signs the exact claims.md bytes. This is the auditor's attestation of
    # the verdict observed; the pack itself is unchanged. No compliance
    # claim is not made or implied by the signature.

    signing_key = Ed25519PrivateKey.generate()
    signature = signing_key.sign(rendered.stdout.encode("utf-8"))
    (laptop_dir / "claims.md.sig").write_text(
        base64.b64encode(signature).decode("ascii") + "\n", encoding="utf-8"
    )
    (laptop_dir / "claims-signing-key.pub").write_bytes(
        signing_key.public_key().public_bytes(
            encoding=ser.Encoding.Raw,
            format=ser.PublicFormat.Raw,
        )
    )
    verify_sig = subprocess.run(
        [
            sys.executable,
            "-c",
            "import base64,sys;from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat;"
            "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey;"
            "pub = Ed25519PublicKey.from_public_bytes(open(sys.argv[1],'rb').read());"
            "pub.verify(base64.b64decode(open(sys.argv[2]).read().strip()), open(sys.argv[3],'rb').read())",
            str(laptop_dir / "claims-signing-key.pub"),
            str(laptop_dir / "claims.md.sig"),
            str(laptop_dir / "claims.md"),
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if verify_sig.returncode != 0:
        raise RolePlayError(f"claim-sheet signature did not verify:\n{verify_sig.stderr}")

    # (6) Honest notes pinned to the artefacts.
    notes = f"""# P1.7V second-laptop role-play notes

Generated by scripts/second_laptop_roleplay.py (the audit pack builder and
verifier do the real work; this directory only holds what the auditor gets).

## What this run was
- A fresh audit pack built by ops/audit-pack/pack.py ({built["counts"]["receipts"]} receipt(s)).
- The pack and verify_pack.py copied here: nothing else of the repository.
- Verification run {("inside a denied network namespace: " + isolation_note) if net_probe else ("with namespace isolation " + isolation_note)}.
- Verdict: GREEN on the pack as shipped; RED (exit 1) on a deliberately
  byte-tampered copy (one trailing newline added to receipts.jsonl).
- claims.md re-rendered from the raw inputs, byte-identical to the pack's
  sheet, no-claim guard header and sentinel present and re-asserted, then
  signed here with a fresh ephemeral Ed25519 key (claims.md.sig,
  claims-signing-key.pub). The signature attests to the sheet as observed,
  not to any compliance claim.

## Honest limits of the simulation
- Same kernel, same machine, one directory: this is a role-play stand-in
  for a second laptop, not a second device. Host configuration outside a
  network namespace (filesystem, entropy, Python install) is shared.
- {isolation_note}
- The signature key is freshly minted per run and carries no identity
  beyond this directory; treat it as a rehearsal artefact, not an
  organisational signature.
- Verification time used the pack's embedded key snapshot; no external
  trust anchor was consulted.
"""
    (laptop_dir / "role-play-notes.md").write_text(notes, encoding="utf-8")

    return {
        "pack_dir": str(src_pack),
        "pack_zip": str(built["zip"]),
        "laptop_dir": str(laptop_dir),
        "laptop_pack": str(laptop_pack),
        "verification_green": green_run.stdout,
        "verification_tamper": tamper_run.stdout,
        "network_probe": net_probe,
        "isolation_note": isolation_note,
        "claim_sheet_signed": str(laptop_dir / "claims.md.sig"),
        "signing_key_pub": str(laptop_dir / "claims-signing-key.pub"),
        "counts": built["counts"],
    }
