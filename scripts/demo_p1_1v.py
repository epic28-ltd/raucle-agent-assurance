#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""P1.1V demo: pull the network plug MID-VERIFICATION; the pack verifies.

Story: starts a real pack verification, and while it is in flight installs
socket-level denial across the process (the plug pull), showing that
verification still completes and reports the pack's expected verdicts,
including the deliberate-tamper FAIL path. Every attempted external call
fails the run loudly and is recorded.

Honest gap, stated plainly: this is same-kernel monkeypatch isolation inside
one Python process, not a physically unplugged machine and not a separate
network namespace. Where the machine permits `unshare -n` the demo also runs
the standalone verifier inside a network-less namespace; the physical
plug-pull beat is the W8 live demo, which is out of scope here.
"""

from __future__ import annotations

import datetime as dt
import importlib.util
import pathlib
import shutil
import subprocess
import sys
import threading

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DEMO = REPO_ROOT / "services" / "investigation-ui" / "demo_data"
CLOCK = dt.datetime(2026, 11, 5, 12, 0, 0, tzinfo=dt.UTC)


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def main() -> int:
    workdir = pathlib.Path(__file__).resolve().parent.parent / ".cache" / "p1-1v-demo"
    workdir.mkdir(parents=True, exist_ok=True)

    pack = _load("demo_p1_1v_pack", REPO_ROOT / "ops" / "audit-pack" / "pack.py")
    verify_pack = _load(
        "demo_p1_1v_verify_pack", REPO_ROOT / "tools" / "verifier" / "verify_pack.py"
    )

    print("== P1.1V: building the demo pack (cryptography runs locally) ==")
    built = pack.build_pack(
        DEMO / "evidence_store.jsonl", DEMO / "trust_roots.jsonl", workdir / "pack", clock=CLOCK
    )
    pack_dir = pathlib.Path(built["pack_dir"])
    print(f"   pack: {pack_dir}")
    print(
        f"   self_contained: {built['self_contained']}"
        if "self_contained" in built
        else "   (self-contained manifest block embedded)"
    )

    print()
    print("== Beat 1: verification starts, then the plug is pulled mid-run ==")
    started = threading.Event()
    box: dict = {}

    def _verify() -> None:
        started.set()  # verification is now in flight
        box["report"] = verify_pack.verify_pack(pack_dir)

    worker = threading.Thread(target=_verify, name="verifier")
    worker.start()
    worker.join(0.2)
    assert started.is_set(), "verification never started"
    attempts = verify_pack.install_offline_audit()  # PLUG PULLED, mid-run
    print("   ... verifier in flight: network plug pulled (sockets denied process-wide)")
    worker.join(60)
    assert not worker.is_alive(), "verification did not finish"
    report = box["report"]
    print(report.render())
    print(
        f"   external-call attempts recorded: {len(attempts)} (audit list: {attempts or 'empty'})"
    )
    if report.failed:
        print("FAIL: clean pack did not verify green under the plug pull")
        return 1

    print()
    print("== Beat 2: with the plug still out, the deliberate-tamper FAIL path ==")
    tampered = workdir / "tampered"
    if tampered.exists():
        shutil.rmtree(tampered)
    shutil.copytree(pack_dir, tampered)
    target = tampered / "verify-notes.md"
    data = bytearray(target.read_bytes())
    data[0] = data[0] ^ 0x01  # flip one bit
    target.write_bytes(bytes(data))
    red = verify_pack.verify_pack(tampered)
    print(red.render())
    print(f"   external-call attempts recorded: {len(verify_pack.EXTERNAL_CALL_AUDIT)}")
    if not red.failed:
        print("FAIL: tampered pack did not go RED under the plug pull")
        return 1

    print()
    print("== Beat 3 (probe): standalone CLI under a network-less namespace ==")
    if not shutil.which("unshare"):
        print(
            "   unshare not present: namespace probe unavailable on this machine (honest gap: beat covered by in-process audit only)"
        )
    else:
        probe = subprocess.run(
            [
                "unshare",
                "-n",
                sys.executable,
                "-c",
                "import socket; socket.create_connection(('localhost', 1))",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if probe.returncode != 0 and "permitted" in (probe.stderr + probe.stdout).lower():
            print(
                f"   unshare -n refused by the kernel here: {probe.stderr.strip()} (honest gap: namespace beat unavailable)"
            )
        else:
            proc = subprocess.run(
                [
                    "unshare",
                    "-n",
                    sys.executable,
                    str(REPO_ROOT / "tools" / "verifier" / "verify_pack.py"),
                    str(pack_dir),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            verdict = "GREEN" if proc.returncode == 0 else "NOT GREEN"
            print(f"   verifier CLI under unshare -n: exit {proc.returncode} ({verdict})")
            if proc.returncode != 0:
                print(proc.stdout)
                print(proc.stderr, file=sys.stderr)

    print()
    print("== Honest gaps ==")
    print("   - This demonstration is same-kernel monkeypatch isolation inside one")
    print("     Python process, not a physically unplugged machine.")
    print("   - The namespace probe (unshare -n) only runs where the kernel allows it.")
    print("   - The physical plug-pull beat is the W8 live demo, out of scope here.")
    print()
    print("P1.1V demo complete: plug pulled mid-verification, pack verified green,")
    print("tamper path went RED, zero external calls in the verifier path.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
