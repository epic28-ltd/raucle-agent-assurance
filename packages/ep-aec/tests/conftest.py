# SPDX-License-Identifier: Apache-2.0
"""Make the optional raucle adapter importable when the ep-aec suite is run
standalone (the repo-root conftest already does this for full-repo runs)."""

from __future__ import annotations

import pathlib
import sys

_tests = pathlib.Path(__file__).resolve().parent
_repo = _tests.parents[2]
_adapter_src = _repo / "packages" / "raucle-adapter" / "src"
if _adapter_src.is_dir():
    sys.path.insert(0, str(_adapter_src))
# Own package too: the suite must import oaa_epaec even where the package is
# not installed (bare CI checkouts only rely on repo layout).
_src = _repo / "packages" / "ep-aec" / "src"
if _src.is_dir():
    sys.path.insert(0, str(_src))
