# SPDX-License-Identifier: Apache-2.0
"""Make the console package importable without installing it."""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))
