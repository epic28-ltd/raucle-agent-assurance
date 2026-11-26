# SPDX-License-Identifier: Apache-2.0
"""Guard for the W3 phase 5 beat's sys.path bootstrap (P1.D3r).

The beat executes raucle-cloud's own test module, whose imports reach
raucle_cloud.portal.replay, which imports raucle.chain_graph. The raucle
wheel pinned into the raucle-cloud venv predates chain_graph, so the beat
must place the checked-out raucle repo ahead of site-packages. This test
loads phase5_beat the way the runbook does and asserts the module resolves
to the repo checkout; it skips cleanly when the sibling repos are absent.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

BEAT = Path(os.environ["OAA_PHASE5_BEAT_PATH"]) if os.environ.get("OAA_PHASE5_BEAT_PATH") else None
RAUCLE_REPO = (
    Path(os.environ["RAUCLE_SOURCE_ROOT"]) if os.environ.get("RAUCLE_SOURCE_ROOT") else None
)
CLOUD_REPO = Path(os.environ["RAUCLE_CLOUD_ROOT"]) if os.environ.get("RAUCLE_CLOUD_ROOT") else None
CLOUD_VENV_PY = (
    Path(os.environ["RAUCLE_CLOUD_PYTHON"])
    if os.environ.get("RAUCLE_CLOUD_PYTHON")
    else (CLOUD_REPO / ".venv" / "bin" / "python" if CLOUD_REPO else None)
)


def test_phase5_beat_resolves_chain_graph_from_repo_checkout() -> None:
    """The beat's path bootstrap must make raucle.chain_graph importable.

    Runs in the raucle-cloud venv, which is the only environment in which
    the stale-wheel problem exists; elsewhere the test skips.
    """
    if BEAT is None or RAUCLE_REPO is None or CLOUD_REPO is None or CLOUD_VENV_PY is None:
        pytest.skip(
            "set OAA_PHASE5_BEAT_PATH, RAUCLE_SOURCE_ROOT and RAUCLE_CLOUD_ROOT "
            "(and optionally RAUCLE_CLOUD_PYTHON) to run the cross-repository beat check"
        )
    if not BEAT.is_file() or not RAUCLE_REPO.is_dir() or not CLOUD_REPO.is_dir():
        pytest.skip("explicit phase-5 beat or sibling checkout path is unavailable")
    if not CLOUD_VENV_PY.is_file():
        pytest.skip("explicit Raucle Cloud Python environment is unavailable")

    script = (
        "import importlib.util, pathlib, sys\n"
        "sys.argv = ['phase5_beat.py']\n"
        "_spec = importlib.util.spec_from_file_location(\n"
        f"    'w3_phase5_beat', pathlib.Path(r'{BEAT}'))\n"
        "_mod = importlib.util.module_from_spec(_spec)\n"
        "_spec.loader.exec_module(_mod)\n"
        "import raucle.chain_graph as cg\n"
        "print(cg.__file__)\n"
    )
    result = subprocess.run([str(CLOUD_VENV_PY), "-c", script], capture_output=True, text=True)
    assert result.returncode == 0, f"beat import failed: {result.stderr}"
    resolved = result.stdout.strip().strip("'\"")
    assert resolved.startswith(str(RAUCLE_REPO)), (
        f"chain_graph resolved outside the repo checkout: {resolved}"
    )
