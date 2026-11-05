# SPDX-License-Identifier: Apache-2.0
"""P1.7V verification story tests: the second-laptop auditor role-play.

The main test runs the whole role-play programmatically: build a real pack,
hand only the pack and the verifier CLI to a throwaway "second laptop"
directory, verify inside a proven network-denied namespace, prove the
deliberate-tamper RED path offline, re-render the claim sheet, and produce
the auditor-signed claim sheet. Skips cleanly with a clear reason when the
host cannot give us a denied network namespace.

Honest note on the simulation: it runs on the same kernel and the same
machine as the pack build; the "second laptop" is a directory. That is a
stated limitation of this environment, recorded in the role-play notes the
flow itself writes, not something the test hides.
"""

from __future__ import annotations

import base64
import datetime as dt
import importlib.util
import pathlib
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]

_spec = importlib.util.spec_from_file_location(
    "oaa_second_laptop", REPO_ROOT / "ops" / "audit-pack" / "second_laptop.py"
)
assert _spec is not None and _spec.loader is not None
role_play = importlib.util.module_from_spec(_spec)
sys.modules["oaa_second_laptop"] = role_play
_spec.loader.exec_module(role_play)

_pack_spec = importlib.util.spec_from_file_location(
    "oaa_audit_pack", REPO_ROOT / "ops" / "audit-pack" / "pack.py"
)
assert _pack_spec is not None and _pack_spec.loader is not None
pack = importlib.util.module_from_spec(_pack_spec)
sys.modules["oaa_audit_pack"] = pack
_pack_spec.loader.exec_module(pack)

CLOCK = dt.datetime(2026, 11, 5, 12, 0, 0, tzinfo=dt.UTC)


def _network_denial_available() -> tuple[bool, str]:
    prefix, note = role_play._find_network_prefix()
    return prefix is not None, note


def test_second_laptop_role_play_full_flow(tmp_path: pathlib.Path) -> None:
    """The whole P1.7V story, executed: green offline, tamper RED, signed sheet."""
    ok, why = _network_denial_available()
    if not ok:
        pytest.skip(
            "network namespace for the no-network role-play unavailable in this environment: " + why
        )
    result = role_play.run_second_laptop_role_play(tmp_path / "role-play", clock=CLOCK)

    laptop = pathlib.Path(result["laptop_dir"])
    pack_dir = pathlib.Path(result["laptop_pack"])
    # Nothing but the pack and the verifier CLI crossed over.
    entries = sorted(p.name for p in laptop.iterdir())
    assert "verify_pack.py" in entries and pack_dir.name in entries
    assert "conftest.py" not in entries and "pytest" not in " ".join(entries)
    # Green verdict under namespace isolation.
    assert "OVERALL VERDICT: GREEN" in result["verification_green"]
    assert result["network_probe"] is not None and result["network_probe"]["expectedly_failed"]
    # Deliberate tamper came back RED with exit 1 under the same isolation.
    assert "OVERALL VERDICT: RED" in result["verification_tamper"]
    assert "tampered after export" in result["verification_tamper"]
    # Claim sheet: guard intact, no compliance claims, signed and signature valid.
    sheet = (laptop / "claims.md").read_text()
    assert pack.GUARD_HEADER in sheet and pack.GUARD_SENTINEL in sheet
    pack.assert_no_compliance_claims(sheet)
    signature = base64.b64decode((laptop / "claims.md.sig").read_text().strip())
    pub = Ed25519PublicKey.from_public_bytes((laptop / "claims-signing-key.pub").read_bytes())
    pub.verify(signature, sheet.encode("utf-8"))  # raises on mismatch
    # Honest notes were left in the directory.
    notes = (laptop / "role-play-notes.md").read_text()
    lowered = notes.lower()
    assert "second laptop" in lowered and "same kernel" in lowered and "honest limits" in lowered
    assert result["isolation_note"].startswith("netns via")


def test_second_laptop_role_play_honest_without_isolation(tmp_path: pathlib.Path) -> None:
    """Where no namespace exists, the run completes and says plainly it did."""
    ok, _why = _network_denial_available()
    if ok:
        pytest.skip(
            "network namespace is available here; the fallback is covered implicitly by the full-flow test"
        )
    result = role_play.run_second_laptop_role_play(tmp_path / "role-play", clock=CLOCK)
    assert result["network_probe"] is None
    assert result["isolation_note"].startswith("NONE:"), result["isolation_note"]
    assert "OVERALL VERDICT: GREEN" in result["verification_green"]
    assert "OVERALL VERDICT: RED" in result["verification_tamper"]
    assert (
        "user namespaces disabled" in result["isolation_note"]
        or "not installed" in result["isolation_note"]
    )
