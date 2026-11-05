# SPDX-License-Identifier: Apache-2.0
"""OV-6 docs-alignment check tests: role documents reference only live artefacts."""

from __future__ import annotations

import pathlib
import subprocess
import textwrap

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check_docs_alignment.py"
ROLES_DIR = REPO / "docs" / "assurance" / "roles"


def _run(*args):
    return subprocess.run(["python3", str(SCRIPT), *args], capture_output=True, text=True)


def test_all_role_documents_align():
    result = _run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


def test_missing_artefact_reference_fails():
    poisoned = ROLES_DIR / "zz-poisoned-check.md"
    poisoned.write_text(
        textwrap.dedent(
            """\
            # Poisoned check document
            See `docs/does/not/exist.md` for details.
            """
        )
    )
    try:
        result = _run()
        assert result.returncode == 1
        assert "docs/does/not/exist.md" in result.stdout
        assert result.stdout.count("FAIL") >= 1
    finally:
        poisoned.unlink()
    assert _run().returncode == 0, "doc set must be self-healing after the check"


def test_missing_role_document_fails():
    real = ROLES_DIR / "leaders.md"
    original = real.read_text()
    real.unlink()
    try:
        result = _run()
        assert result.returncode == 1
        assert "missing role document: leaders.md" in result.stdout
    finally:
        real.write_text(original)
    assert (ROLES_DIR / "leaders.md").read_text() == original
    assert _run().returncode == 0
