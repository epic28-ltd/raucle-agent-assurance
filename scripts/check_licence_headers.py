"""Enforce the Apache-2.0 SPDX licence headers documented in LICENSING.md.

The repository is Apache-2.0 permanently (ADR-0006; LICENSING.md is the
governing text): every ``.py`` file in the mapped tree must carry
``SPDX-License-Identifier: Apache-2.0`` — placed as a comment right after
the module docstring, or at file top when the module has no docstring.

A file fails the check when it lacks the identifier, or when it carries an
additional conflicting identifier (an ambiguous claim fails both ways).

Run: ``python3 scripts/check_licence_headers.py`` (wired into ci.yml before
pytest). Exits 1 listing every offending file; exits 0 and prints the count
when the whole mapping is clean.
"""

from __future__ import annotations

import os
import re
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

APACHE_DIRS = [
    "packages",
    "services",
    "tests",
]
APACHE_ID = "Apache-2.0"

MAPPING = [(APACHE_DIRS, APACHE_ID)]

SPDX_LINE_RE = re.compile(r"^\s*#\s*SPDX-License-Identifier:\s*([^\s#]+)")

WALK_SKIP_DIRS = {"__pycache__", "node_modules", ".venv", "uv-virtualenv"}


def py_files(rel_dir: str) -> list[str]:
    """All ``.py`` files under ``rel_dir`` in the working tree (gitignored content included is fine: a headerless scratch file failing CI is the correct failure mode)."""
    base = os.path.join(REPO_ROOT, rel_dir)
    out: list[str] = []
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in sorted(dirs) if not d.startswith(".") and d not in WALK_SKIP_DIRS]
        for name in sorted(files):
            if name.endswith(".py"):
                out.append(os.path.join(root, name))
    return sorted(out)


def spdx_ids(path: str) -> set[str]:
    ids: set[str] = set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            match = SPDX_LINE_RE.match(line)
            if match:
                ids.add(match.group(1))
    return ids


def main() -> int:
    failures: list[str] = []
    checked = 0
    for dirs, expected in MAPPING:
        for rel_dir in dirs:
            for path in py_files(rel_dir):
                checked += 1
                rel = os.path.relpath(path, REPO_ROOT)
                ids = spdx_ids(path)
                if expected not in ids:
                    failures.append(f"{rel}: missing SPDX-License-Identifier: {expected}")
                elif ids != {expected}:
                    failures.append(
                        f"{rel}: conflicting SPDX identifiers {sorted(ids)}; "
                        f"expected exactly {expected}"
                    )
    if failures:
        print(f"LICENCE HEADER CHECK FAILED ({len(failures)} file(s)):", file=sys.stderr)
        for failure in failures:
            print(f"  {failure}", file=sys.stderr)
        print(
            f"Checked {checked} files across {len(APACHE_DIRS)} Apache-2.0 "
            f"directory roots. Fix the headers above (see LICENSING.md).",
            file=sys.stderr,
        )
        return 1
    print(
        f"licence headers OK: {checked} files "
        f"(Apache-2.0 across {len(APACHE_DIRS)} directory roots)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
