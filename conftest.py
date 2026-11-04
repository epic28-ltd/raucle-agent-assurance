# SPDX-License-Identifier: Apache-2.0
"""Make packages/raucle-adapter/src importable without installing the package."""

import pathlib
import sys

sys.path.insert(
    0, str(pathlib.Path(__file__).resolve().parent / "packages" / "raucle-adapter" / "src")
)
sys.path.insert(
    0,
    str(pathlib.Path(__file__).resolve().parent / "services" / "correlation" / "src"),
)
