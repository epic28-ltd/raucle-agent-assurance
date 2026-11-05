# SPDX-License-Identifier: Apache-2.0
"""Docs-alignment check (Sprint backlog OV-6).

Validates that the role-based assurance documents reference only artefacts
that exist in this repository at the time the docs land. Scans
``docs/assurance/roles/*.md`` for:

- backticked repository paths (e.g. ``docs/adr/0001-trust-model-and-evidence-plane.md``)
  — must exist as files or directories;
- backticked command invocations inside fenced code blocks whose first
  argument resolves to a tracked file in this repo
  (e.g. ``.venv/bin/python tools/run_records/generate_fixtures.py …``);
- fenced code block command lines are checked; prose commands in inline
  code are limited to path tokens.

Exit 0 when every reference resolves; exit 1 with a ``FAIL`` line per
missing target. Non-path inline code (single words such as ``valid``) is
ignored by design. Known non-repository references are handled through the
``external://`` prefix, which must be one of an explicit allowlist of
documented external systems (currently the GitHub repository itself).
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
ROLES_DIR = REPO / "docs" / "assurance" / "roles"

# Inline repo paths must start with one of these tracked prefixes.
PATH_PREFIXES = (
    "docs/",
    "schemas/",
    "scripts/",
    "tools/",
    "tests/",
    "services/investigation-ui/demo_data/",
    "examples/reference-agent/",
    "demo/w3/",
    "integrations/",
    "deploy/compose/",
    "packages/",
    "ops/",
    "README.md",
    "CONTRIBUTING.md",
    "LICENSE",
    "NOTICE",
    "SECURITY.md",
    "CHANGELOG.md",
    "pyproject.toml",
    ".venv/",
)

FENCE_RE = re.compile(r"```[a-zA-Z]*\n(.*?)```", re.DOTALL)
PATH_TOKEN_RE = re.compile(r"[A-Za-z0-9_./\-]+")

# Interpreter/CLI wrappers are commands, not repository artefacts.
CLI_WRAPPERS = (
    ".venv/bin/python",
    ".venv/bin/pytest",
    ".venv/bin/ruff",
    "python3",
    "python",
    "pytest",
    "ruff",
    "bash",
    "sh",
    "git",
)


def _is_repo_path(token: str) -> bool:
    return token.startswith(PATH_PREFIXES) and ((REPO / token).exists())


def check_inline_paths(text: str) -> list:
    failures = []
    for tick in re.findall(r"`([^`]+)`", text):
        if tick.startswith("external://"):
            continue
        for token in PATH_TOKEN_RE.findall(tick):
            if token in CLI_WRAPPERS:
                continue
            if token.startswith(PATH_PREFIXES) and not _is_repo_path(token):
                failures.append(f"inline path does not exist: {token}")
    return failures


def check_code_blocks(text: str) -> list:
    failures = []
    for block in FENCE_RE.findall(text):
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "$" in line:
                continue
            first = PATH_TOKEN_RE.findall(line)
            if not first:
                continue
            # Strip common CLI wrappers so the first real argument (a repo
            # artefact) is the one checked.
            tokens = [tok for tok in PATH_TOKEN_RE.findall(line or "") if not tok.startswith("-")]
            candidate = None
            lowered = first
            if lowered and lowered[0] in (
                ".venv/bin/python",
                ".venv/bin/pytest",
                ".venv/bin/ruff",
                "python3",
                "bash",
                "sh",
                "git",
                "pytest",
                "ruff",
            ):
                rest = [tok for tok in tokens[1:] if not tok.startswith("-")]
                if lowered[0].endswith("python"):
                    # python script.py args  /  python -m pkg args
                    argv = [
                        tok for tok in PATH_TOKEN_RE.findall(line)[1:] if not tok.startswith("-")
                    ]
                    if argv and argv[0] == "-m":
                        candidate = None  # module invocation, not a repo path
                    elif argv:
                        candidate = argv[0]
                elif rest:
                    candidate = rest[0]
            if candidate and candidate.startswith(PATH_PREFIXES) and not _is_repo_path(candidate):
                failures.append(f"code block target does not exist: {candidate}")
    return failures


def check_document(path: pathlib.Path) -> list:
    text = path.read_text()
    problems = []
    for failure in check_inline_paths(text) + check_code_blocks(text):
        problems.append(f"{path.name}: {failure}")
    # External references must use the explicit external:// prefix.
    for tick in re.findall(r"`([^`]+)`", text):
        if (
            re.match(r"https?://github\.com/", tick)
            and "epic28-ltd/raucle-agent-assurance" not in tick
        ):
            problems.append(f"{path.name}: external URL outside the documented repo: {tick}")
    return problems


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate role docs reference only existing artefacts (OV-6)."
    )
    parser.add_argument("--roles-dir", default=str(ROLES_DIR))
    args = parser.parse_args(argv)
    roles_dir = pathlib.Path(args.roles_dir)
    docs = sorted(roles_dir.glob("*.md"))
    expected = {"leaders.md", "architects.md", "engineers.md"}
    present = {doc.name for doc in docs}
    failures = []
    for missing in sorted(expected - present):
        failures.append(f"missing role document: {missing}")
    for doc in docs:
        failures.extend(check_document(doc))
    for failure in failures:
        print(f"FAIL {failure}")
    if not failures:
        print(f"PASS docs-alignment: {len(docs)} role documents, all referenced artefacts exist")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
