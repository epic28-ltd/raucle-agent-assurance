# SPDX-License-Identifier: Apache-2.0
"""Raucle Console - EPIC-N application shell for the Raucle agent suite."""

__all__ = ["app", "create_app"]


def __getattr__(name):
    # Lazy re-export: the console module itself imports only when first
    # accessed, so ``import raucle_console`` stays cheap.
    if name in __all__:
        from raucle_console import app as _app  # noqa: PLC0415

        return getattr(_app, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
