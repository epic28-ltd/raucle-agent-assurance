"""UI-01 test setup: point the offline verifier at the pinned raucle
worktree when it is present (optional, env-driven at runtime). Committed
tests skip the raucle-dependent assertions gracefully when raucle is not
importable in the current environment."""
# SPDX-License-Identifier: Apache-2.0

import importlib.util
import os
import pathlib

_DEFAULT_WORKTREE = pathlib.Path.home() / "Projects" / "oaa-spike-4nov" / "evd" / "raucle-63edacd"

if (
    importlib.util.find_spec("raucle") is None
    and (_DEFAULT_WORKTREE / "raucle" / "__init__.py").is_file()
):
    os.environ.setdefault("OAA_RAUCLE_SRC", str(_DEFAULT_WORKTREE))
