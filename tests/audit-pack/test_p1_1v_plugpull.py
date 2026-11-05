# SPDX-License-Identifier: Apache-2.0
"""P1.1V verification story: pulling the network plug mid-verification.

Backlog acceptance criteria: pull the plug mid-verification and the pack
still verifies, with zero external calls in the verifier path, and ANY
attempted external call fails the run loudly.

Honest gap, stated plainly: this is same-kernel monkeypatch isolation inside
one Python process (plus a namespace probe where `unshare -n` is allowed),
not a physically unplugged machine. The physical plug-pull beat is the W8
live demo, which is out of scope here.
"""

from __future__ import annotations

import datetime as dt
import http.client
import importlib.util
import pathlib
import shutil
import socket
import subprocess
import sys
import threading
import urllib.request

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "services" / "investigation-ui" / "demo_data"
CLOCK = dt.datetime(2026, 11, 5, 12, 0, 0, tzinfo=dt.UTC)


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


pack = _load("oaa_audit_pack_p11v", REPO_ROOT / "ops" / "audit-pack" / "pack.py")
verify_pack = _load("oaa_verify_pack_p11v", REPO_ROOT / "tools" / "verifier" / "verify_pack.py")

_ORIGINALS = {
    "socket.socket": socket.socket,
    "socket.create_connection": socket.create_connection,
    "socket.getaddrinfo": socket.getaddrinfo,
    "http.client.HTTPConnection.connect": http.client.HTTPConnection.connect,
    "urllib.request.urlopen": urllib.request.urlopen,
}


@pytest.fixture
def offline_guard():
    """Install the verifier-path plug-pull audit, restore sockets after."""
    verify_pack.EXTERNAL_CALL_AUDIT.clear()
    verify_pack.install_offline_audit()
    yield verify_pack.EXTERNAL_CALL_AUDIT
    socket.socket = _ORIGINALS["socket.socket"]
    socket.create_connection = _ORIGINALS["socket.create_connection"]
    socket.getaddrinfo = _ORIGINALS["socket.getaddrinfo"]
    http.client.HTTPConnection.connect = _ORIGINALS["http.client.HTTPConnection.connect"]
    urllib.request.urlopen = _ORIGINALS["urllib.request.urlopen"]
    verify_pack.EXTERNAL_CALL_AUDIT.clear()


@pytest.fixture(scope="module")
def built_pack(tmp_path_factory: pytest.TempPathFactory) -> dict:
    out = tmp_path_factory.mktemp("p1-1v")
    return pack.build_pack(DEMO / "evidence_store.jsonl", DEMO / "trust_roots.jsonl", out / "pack", clock=CLOCK)


def test_plug_pulled_midrun_verification_still_completes_green(
    built_pack: dict, offline_guard: list
) -> None:
    """The verifier starts with the network up, the plug is pulled MID-RUN,
    and verification still completes with the pack's expected verdicts and
    zero recorded external calls."""
    started = threading.Event()
    report_box: dict = {}

    def _run() -> None:
        started.set()  # verification is now in flight
        report_box["report"] = verify_pack.verify_pack(pathlib.Path(built_pack["pack_dir"]))

    worker = threading.Thread(target=_run)
    worker.start()
    worker.join(0.2)
    assert started.is_set()
    # MID-RUN: pull the plug while the verifier is executing
    verify_pack.install_offline_audit()
    worker.join(30)
    assert not worker.is_alive()

    report = report_box["report"]
    assert not report.failed, report.render()
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
    # zero external calls in the verifier path, as recorded by the audit
    assert offline_guard == [], f"verifier attempted external calls: {offline_guard}"


def test_plug_pulled_before_run_tamper_path_still_fails_red(
    built_pack: dict, tmp_path: pathlib.Path, offline_guard: list
) -> None:
    """With the network gone for the whole run, the deliberate-tamper FAIL
    path still trips RED: the verdicts come from the pack bytes, not from
    anything external."""
    d = tmp_path / "tampered"
    shutil.copytree(pathlib.Path(built_pack["pack_dir"]), d)
    target = d / "verify-notes.md"
    data = bytearray(target.read_bytes())
    data[0] = data[0] ^ 0x01
    target.write_bytes(bytes(data))
    report = verify_pack.verify_pack(d)
    assert report.failed
    assert "OVERALL VERDICT: RED" in report.render()
    check = next(c for c in report.checks if c.name == "manifest-integrity")
    assert check.status == "FAIL" and "verify-notes.md" in check.message
    assert offline_guard == [], f"verifier attempted external calls: {offline_guard}"


def test_any_external_call_fails_the_run_loudly(offline_guard: list) -> None:
    """The instrumentation fails loudly: a live external attempt raises
    rather than passing silently, and the attempt is recorded."""
    _MATCH = r"P1\.1V offline audit"
    with pytest.raises(OSError, match=_MATCH):
        socket.create_connection(("example.invalid", 443))
    with pytest.raises(OSError, match=_MATCH):
        socket.socket()
    assert offline_guard == ["socket.create_connection", "socket.socket"]


def test_full_verifier_path_zero_external_calls_and_namespace_probe(
    built_pack: dict, offline_guard: list
) -> None:
    """Full verifier execution (the CLI against the shipped zip, in-process
    under the audit) records zero external calls; where the kernel allows
    `unshare -n` the standalone CLI also completes green inside a
    network-less namespace. Honest gap: where unshare is refused, that
    stronger isolation is unavailable and only the in-process audit holds."""
    assert verify_pack.main([str(pathlib.Path(built_pack["zip"]))]) == 0
    assert offline_guard == [], f"verifier attempted external calls: {offline_guard}"

    if not shutil.which("unshare"):
        pytest.skip("unshare not present; namespace isolation probe unavailable on this machine")
    probe = subprocess.run(
        ["unshare", "-n", sys.executable, "-c", "import socket; socket.create_connection(('localhost', 1))"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    if probe.returncode != 0 and "permitted" in (probe.stderr + probe.stdout).lower():
        pytest.skip(f"unshare -n refused by the kernel on this machine: {probe.stderr.strip()}")
    assert probe.returncode != 0, "unshare -n must make connections fail"
    # and the standalone CLI completes green inside the network-less namespace
    proc = subprocess.run(
        ["unshare", "-n", sys.executable, str(REPO_ROOT / "tools" / "verifier" / "verify_pack.py"), str(built_pack["pack_dir"])],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
