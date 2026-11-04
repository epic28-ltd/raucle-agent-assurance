# SPDX-License-Identifier: Apache-2.0
"""Optional pytest wrapper for the COR-01 Langfuse smoke — skips without the stack."""

from __future__ import annotations

import importlib.util
import pathlib

import pytest

SMOKE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "services"
    / "correlation"
    / "integrations"
    / "langfuse_smoke.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("langfuse_smoke", SMOKE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_langfuse_smoke_attach_and_readback():
    mod = _load()
    if not mod._health(mod.DEFAULT_URL, timeout=3.0):
        pytest.skip(f"Langfuse stack not reachable at {mod.DEFAULT_URL}")
    out = mod.run_smoke()
    assert out["ok"], out
    assert out["correlation_state"] == "matched"
