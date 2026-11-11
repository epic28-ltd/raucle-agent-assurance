"""Make the console package importable without installing it."""
# SPDX-License-Identifier: FSL-1.1-ALv2

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))
