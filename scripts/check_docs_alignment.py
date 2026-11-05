# SPDX-License-Identifier: Apache-2.0
"""Docs-alignment check (Sprint backlog OV-6, fence-aware parser OV-15).

Validates that the role-based assurance documents reference only artefacts
that exist in this repository at the time the docs land. Scans
``docs/assurance/roles/*.md`` for:

- backticked repository paths (e.g. ``docs/adr/0001-trust-model-and-evidence-plane.md``)
  — must exist as files or directories;
- command invocations inside fenced code blocks whose first argument resolves
  to a tracked file in this repo
  (e.g. ``.venv/bin/python tools/run_records/generate_fixtures.py …``).

Parsing (OV-15) is line/block aware, not regex-global. Triple-fence state is
tracked line by line, inline code scanning runs only outside fences, and a
bash fence's content is still checked (per the role-docs design). An
unpaired backtick or an unclosed fence is a *named* ``FAIL`` — fail-visible,
never the silent cross-line mis-pairing of the previous text-global backtick
regex, which could swallow subsequent inline spans. Non-bash fences are
reported by name so their content is never silently unexamined. Every
inline code span found is recorded.

Exit 0 when every reference resolves; exit 1 with a ``FAIL`` line per
missing target or warning. Non-path inline code (single words such as
``valid``) is ignored by design. Known non-repository references are handled
through the ``external://`` prefix, which must be one of an explicit
allowlist of documented external systems (currently the GitHub repository
itself).
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

PATH_TOKEN_RE = re.compile(r"[A-Za-z0-9_./\-]+")
FENCE_LINE_RE = re.compile(r"^\s*(`{3,}|~{3,})\s*([^`]*?)\s*$")

# Fence languages whose content is checked for command targets. The
# role-docs design permits command blocks in bash/shell; any other fence
# language is reported by name (fail-visible) rather than silently skipped.
CHECKED_FENCE_LANGS = frozenset({"bash", "sh", "shell"})

# Fences whose language tag makes their content command code even without an
# explicit tag match (the indented/plain-block legacy form is out of scope).
# Interpreter/CLI wrappers are commands, not repository artefacts.
CLI_WRAPPERS = frozenset(
    {
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
    }
)

# Fence openers that take a command-line-style wrapper in arg 1.
COMMAND_FIRST_TOKENS = frozenset(
    {".venv/bin/python", ".venv/bin/pytest", ".venv/bin/ruff", "python3", "pytest", "ruff"}
)


def _is_repo_path(token: str) -> bool:
    return token.startswith(PATH_PREFIXES) and ((REPO / token).exists())


class Span(dict):
    """A recorded code span: kind, 1-indexed line number, raw content."""


def _inline_spans_on_line(line: str, line_no: int, spans: list, failures: list) -> None:
    """Record paired inline spans on one fence-free line.

    An odd number of backticks means the line never closes its last span:
    that is a named failure (the old regex would have mis-paired it against
    a backtick on a later line and silently swallowed text in between).
    The paired spans found before the dangling backtick are still recorded,
    so nothing before the breakpoint is skipped either.
    """
    segments = line.split("`")
    if len(segments) % 2 == 0:
        failures.append(f"unpaired backtick on line {line_no} (line does not close its code span)")
        # Pairing is unknowable, so record everything after the first
        # backtick as one unterminated span and check it, rather than
        # dropping the tail (which would silently skip later inline paths).
        spans.append(
            {
                "kind": "inline",
                "line_no": line_no,
                "content": "`".join(segments[1:]),
                "unpaired": True,
            }
        )
        return
    for index in range(1, len(segments) - 1, 2):
        content = segments[index]
        if content:
            spans.append({"kind": "inline", "line_no": line_no, "content": content})


def parse_document(text: str) -> tuple[list, list]:
    """Parse a markdown document into code spans plus named warnings.

    Returns (spans, warnings). Spans carry ``kind`` (``inline`` or
    ``fence``), the 1-indexed ``line_no`` they were found on, and the raw
    ``content``. Fence spans are recorded per content line of a fence whose
    language is in ``CHECKED_FENCE_LANGS``. Warnings cover unpaired
    backticks, unclosed fences, and fence languages outside the checked set.
    """
    spans: list = []
    warnings: list = []
    in_fence = False
    fence_open_marker = ""
    fence_lang = ""
    fence_start = 0
    for line_no, raw in enumerate(text.splitlines(), start=1):
        match = FENCE_LINE_RE.match(raw)
        if match is not None:
            marker = match.group(1)
            info = match.group(2).strip()
            if not in_fence:
                in_fence = True
                fence_open_marker = marker[0]
                fence_start = line_no
                fence_lang = info.split()[0] if info else ""
                if fence_lang and fence_lang not in CHECKED_FENCE_LANGS:
                    warnings.append(
                        f"non-bash fence (language {fence_lang!r}) opened on line {line_no}"
                    )
                elif not fence_lang:
                    warnings.append(f"fence with no language tag opened on line {line_no}")
            elif marker[0] == fence_open_marker:
                in_fence = False
                fence_open_marker = ""
                fence_lang = ""
            continue
        if in_fence and fence_lang in CHECKED_FENCE_LANGS:
            spans.append({"kind": "fence", "line_no": line_no, "content": raw})
            continue
        if in_fence:
            continue  # unchecked-language fence content is recorded above, never scanned
        _inline_spans_on_line(raw, line_no, spans, warnings)
    if in_fence:
        warnings.append(f"unclosed fence opened on line {fence_start}")
    return spans, warnings


def check_inline_span(span: dict) -> list:
    """Path-token check on one inline code span (same allowlist contract)."""
    failures = []
    tick = span["content"]
    if tick.startswith("external://"):
        return failures
    for token in PATH_TOKEN_RE.findall(tick):
        if token in CLI_WRAPPERS:
            continue
        if token.startswith(PATH_PREFIXES) and not _is_repo_path(token):
            failures.append(f"inline path does not exist: {token}")
    return failures


def check_fence_lines(fence_spans: list) -> list:
    """Command-target check over recorded fence content lines.

    Preserves the OV-6 semantics: CLI wrappers are stripped so the first
    real argument (the repo artefact) is the one checked, ``-m`` module
    invocations are not repo paths, and ``$``-prompts / comments are prose,
    not commands.
    """
    failures = []
    for span in fence_spans:
        line = span["content"].strip()
        if not line or line.startswith("#") or "$" in line:
            continue
        tokens = PATH_TOKEN_RE.findall(line)
        if not tokens:
            continue
        non_flag = [tok for tok in tokens if not tok.startswith("-")]
        if not non_flag:
            continue
        first = non_flag[0]
        argv = non_flag[1:]
        candidate = None
        if first in COMMAND_FIRST_TOKENS or first in {"bash"}:
            if first.endswith("python"):
                if argv and argv[0] == "-m":
                    candidate = None  # module invocation, not a repo path
                elif argv:
                    candidate = argv[0]
            elif argv:
                candidate = argv[0]
        elif first == "sh" and argv:
            script = argv[0]
            candidate = script if script.startswith(PATH_PREFIXES) else None
        if candidate and candidate.startswith(PATH_PREFIXES) and not _is_repo_path(candidate):
            failures.append(f"code block target does not exist: {candidate}")
    return failures


def check_document(path: pathlib.Path) -> list:
    text = path.read_text()
    spans, warnings = parse_document(text)
    problems: list = []
    for warning in warnings:
        problems.append(f"{path.name}: {warning}")
    fence_spans = []
    for span in spans:
        span_kind = span["kind"]
        if span_kind == "fence":
            fence_spans.append(span)
            continue
        for failure in check_inline_span(span):
            problems.append(f"{path.name}: {failure} (line {span['line_no']})")
    for failure in check_fence_lines(fence_spans):
        problems.append(f"{path.name}: {failure}")
    # External references must use the explicit external:// prefix.
    for span in spans:
        tick = span["content"]
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
