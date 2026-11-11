"""Enforce import direction: the Apache-2.0 audit path never imports FSL code.

The audit-facing surfaces (``packages/``, ``services/assurance_packet``,
``services/independent-assurance``) must stay runnable by an auditor who is
refused access to the FSL-1.1-ALv2 engine surface, so they are forbidden from
importing any module that lives under an FSL-1.1-ALv2 directory
(``services/correlation``, ``services/prebind``, ``services/rules``,
``services/quality``, ``services/console``, ``services/investigation-ui``,
``services/evidence-index``). See LICENSING.md ("Import direction").

Mechanics:

- Every top-level importable package/module name that lives under an FSL
  directory is collected from the tree (``<fsl-dir>/src/<pkg>/__init__.py``
  packages and ``<fsl-dir>/src/<mod>.py`` single modules, at any depth).
- Every ``import`` / ``from X import ...`` statement (absolute, ``level == 0``)
  in an audit-path file is parsed with :mod:`ast`; a forbidden top-level name
  fails the check. Relative imports (``level > 0``) resolve inside the
  importing audit-path package itself and cannot reach an FSL directory, so
  they are ignored by construction.
- Dynamic imports (``importlib.import_module``) are not an escape hatch:
  importing FSL code by any route breaks the audit-path guarantee, so keep
  the audit path free of the names entirely.

Run: ``python3 scripts/check_import_direction.py`` (wired into ci.yml before
pytest, next to check_licence_headers.py). Exits 1 listing every violation.
"""

from __future__ import annotations

import ast
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The audit path that must be self-contained against the FSL engine surface.
AUDIT_DIRS = [
    "packages",
    "services/assurance_packet",
    "services/independent-assurance",
]

# Licence mapping mirrors LICENSING.md / check_licence_headers.py.
FSL_DIRS = [
    "services/correlation",
    "services/prebind",
    "services/rules",
    "services/quality",
    "services/console",
    "services/investigation-ui",
    "services/evidence-index",
]

WALK_SKIP_DIRS = {"__pycache__", "node_modules", ".venv", "uv-virtualenv"}


def py_files(rel_dir: str) -> list[str]:
    base = os.path.join(REPO_ROOT, rel_dir)
    out: list[str] = []
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in sorted(dirs) if not d.startswith(".") and d not in WALK_SKIP_DIRS]
        for name in sorted(files):
            if name.endswith(".py"):
                out.append(os.path.join(root, name))
    return sorted(out)


def fsl_top_level_names() -> set[str]:
    """Importable names defined under any FSL directory."""
    names: set[str] = set()
    for rel_dir in FSL_DIRS:
        for path in py_files(rel_dir):
            rel = os.path.relpath(path, os.path.join(REPO_ROOT, rel_dir))
            parts = rel.replace(os.sep, "/").split("/")
            # src/<pkg>/... layouts: the first component under src/ is the
            # importable name; flat layouts (mod at the dir root) use the
            # module's own name.
            if parts[0] == "src" and len(parts) > 2:
                names.add(parts[1])
            elif len(parts) == 2 or parts[0] != "src":
                names.add(parts[-1][: -len(".py")])
    names.discard("src")
    return names


def absolute_import_toplevels(tree: ast.AST) -> set[str]:
    tops: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            # import statements are absolute by definition in py3 syntax
            for alias in node.names:
                tops.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            tops.add(node.module.split(".")[0])
    return tops


def main() -> int:
    forbidden = fsl_top_level_names()
    violations: list[str] = []
    checked = 0
    for rel_dir in AUDIT_DIRS:
        for path in py_files(rel_dir):
            try:
                with open(path, encoding="utf-8") as fh:
                    tree = ast.parse(fh.read())
            except SyntaxError as exc:  # fail loudly, audit path must parse
                violations.append(f"{os.path.relpath(path, REPO_ROOT)}: syntax error: {exc}")
                continue
            checked += 1
            rel = os.path.relpath(path, REPO_ROOT)
            for top in sorted(absolute_import_toplevels(tree)):
                if top in forbidden:
                    violations.append(
                        f"{rel}: imports FSL-surface module '{top}' — the "
                        f"Apache-2.0 audit path must not import FSL-1.1-ALv2 "
                        f"code (LICENSING.md, Import direction)"
                    )
    if violations:
        print(f"IMPORT DIRECTION CHECK FAILED ({len(violations)} violation(s)):", file=sys.stderr)
        for violation in violations:
            print(f"  {violation}", file=sys.stderr)
        print(
            f"Checked {checked} audit-path files; forbidden FSL top-level "
            f"names: {sorted(forbidden)}.",
            file=sys.stderr,
        )
        return 1
    print(
        f"import direction OK: {checked} audit-path files "
        f"(packages/, services/assurance_packet, services/independent-assurance) "
        f"import no FSL-surface module ({len(forbidden)} forbidden top-level names: "
        f"{sorted(forbidden)})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
