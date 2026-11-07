# SPDX-License-Identifier: Apache-2.0
"""Tripwire: the raucle distribution pin must fail named, never silently drift."""

from __future__ import annotations

import sys
import types

import pytest

from oaa_raucle_adapter.evidence_plane import (
    RAUCLE_DISTRIBUTION_PIN,
    DistributionPinDrift,
    _raucle,
)


@pytest.fixture
def fake_raucle(monkeypatch: pytest.MonkeyPatch):
    """A minimal raucle module with gateway + provenance importable."""
    raucle = types.ModuleType("raucle")
    raucle.__version__ = "9.9.9"
    gateway = types.ModuleType("raucle.gateway")
    provenance = types.ModuleType("raucle.provenance")
    gateway.__path__ = []  # type: ignore[attr-defined]
    provenance.__path__ = []  # type: ignore[attr-defined]

    def fake_import(name, *a, **k):
        for m in (raucle, gateway, provenance):
            sys.modules.setdefault(m.__name__, m)
        return sys.modules[name]

    monkeypatch.setattr("oaa_raucle_adapter.evidence_plane.importlib.import_module", fake_import)
    monkeypatch.setitem(sys.modules, "raucle", raucle)
    monkeypatch.setitem(sys.modules, "raucle.gateway", gateway)
    monkeypatch.setitem(sys.modules, "raucle.provenance", provenance)
    return raucle


def test_pin_passes_on_matching_version(fake_raucle, monkeypatch):
    monkeypatch.setattr(
        "oaa_raucle_adapter.evidence_plane._inst_raucle_version", lambda m: "0.23.5"
    )
    assert _raucle() is fake_raucle


def test_pin_raises_named_on_drift(fake_raucle, monkeypatch):
    monkeypatch.setattr(
        "oaa_raucle_adapter.evidence_plane._inst_raucle_version", lambda m: "0.23.9"
    )
    with pytest.raises(DistributionPinDrift) as excinfo:
        _raucle()
    assert RAUCLE_DISTRIBUTION_PIN in str(excinfo.value)
    assert "0.23.9" in str(excinfo.value)
