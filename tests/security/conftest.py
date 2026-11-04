# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Open Agent Assurance contributors
"""Make packages/instrumentation/src importable without installing the package."""

import pathlib
import sys

_INSTRUMENTATION_SRC = (
    pathlib.Path(__file__).resolve().parents[2] / "packages" / "instrumentation" / "src"
)
sys.path.insert(0, str(_INSTRUMENTATION_SRC))
