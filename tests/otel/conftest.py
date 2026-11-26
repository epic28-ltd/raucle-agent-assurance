# SPDX-License-Identifier: Apache-2.0
"""Make the instrumentation package and the LangGraph adapter importable in tests."""

import pathlib
import sys

_INSTRUMENTATION_SRC = (
    pathlib.Path(__file__).resolve().parents[2] / "packages" / "instrumentation" / "src"
)
_ADAPTER_SRC = (
    pathlib.Path(__file__).resolve().parents[2] / "integrations" / "langgraph-adapter" / "src"
)
sys.path.insert(0, str(_INSTRUMENTATION_SRC))
sys.path.insert(0, str(_ADAPTER_SRC))
