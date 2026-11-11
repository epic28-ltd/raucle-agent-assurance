# SPDX-License-Identifier: Apache-2.0
"""In-process unit tests for scripts/check_docs_alignment.py itself.

The subprocess-driven OV-6 tests (test_check_docs_alignment.py) exercise the
CLI entrypoint on the real role docs; they measure almost nothing of the
checker's own module coverage (dark-corners audit: the docs-alignment
checker was 31% — the docs checker itself must be tested). These tests
import the module directly and pin each documented behaviour: fence-state
parsing, inline-span recovery on unpaired backticks, the external://
allowlist, the CLI-wrapper stripping in fence targets, and main()'s
exit codes.
"""

from __future__ import annotations

import importlib.util
import pathlib
import textwrap

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check_docs_alignment.py"

ROLES_MD = textwrap.dedent(
    """\
    # Role: engineers
    Run `.venv/bin/python scripts/check_docs_alignment.py`.
    Paths: `README.md` and `tools/run_records` are tracked.
    ```bash
    .venv/bin/python scripts/check_docs_alignment.py --roles-dir docs/assurance/roles
    ```
    See `external://github.com/epic28-ltd/raucle` for the upstream.
    """
)


@pytest.fixture(scope="module")
def cda():
    spec = importlib.util.spec_from_file_location("check_docs_alignment", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _doc(tmp_path, name="z.md", text=""):
    path = tmp_path / name
    path.write_text(text)
    return path


# ---------------------------------------------------------------------------
# parse_document: fence state machine + inline spans
# ---------------------------------------------------------------------------


def test_parse_document_records_bash_fence_lines_and_inline_spans(cda):
    text = "before `x` after\n```bash\necho hi\n```\n`tail`\n"
    spans, warnings = cda.parse_document(text)
    fence = [s for s in spans if s["kind"] == "fence"]
    inline = [s for s in spans if s["kind"] == "inline"]
    assert [(f["line_no"], f["content"]) for f in fence] == [(3, "echo hi")]
    assert [s["content"] for s in inline] == ["x", "tail"]
    assert warnings == []


def test_parse_document_names_no_language_tag_and_skips_its_content(cda):
    spans, warnings = cda.parse_document("```\ndocs/nope.md\n```\n")
    assert spans == []  # content of an untagged fence is never scanned
    assert any("fence with no language tag" in w for w in warnings)


def test_parse_document_names_non_bash_fence_language(cda):
    _, warnings = cda.parse_document("```python\nx = 1\n```\n")
    assert any(repr("python") in w for w in warnings)


def test_parse_document_unclosed_fence_is_named_with_line_number(cda):
    _, warnings = cda.parse_document("```bash\necho hi\n")
    assert any("unclosed fence opened on line 1" in w for w in warnings)


def test_parse_document_tilde_fence_content_is_only_checked_when_tagged_bash(cda):
    spans, warnings = cda.parse_document("~~~shell\nscripts/x.py\n~~~\n~~~python\ny\n~~~\n")
    assert [(s["line_no"], s["content"]) for s in spans] == [(2, "scripts/x.py")]
    assert any(repr("python") in w for w in warnings)


def test_parse_document_backticks_inside_fence_do_not_close_fences(cda):
    # A fence containing a triple-quote line must not mis-close early, and
    # a fence line mentioning `inline` backticks is fence content, not spans.
    spans, warnings = cda.parse_document("```bash\nline with ` tick\n```\ntail `a`\n")
    fence = [s for s in spans if s["kind"] == "fence"]
    inline = [s for s in spans if s["kind"] == "inline"]
    assert len(fence) == 1
    assert [s["content"] for s in inline] == ["a"]
    assert warnings == []


def test_unpaired_backtick_records_the_tail_span(cda):
    spans, warnings = cda.parse_document("a `one` b `half-open` more text`\n")
    inline = [s for s in spans if s["kind"] == "inline"]
    # The tail after the first dangling tick is one unterminated span: the
    # pre-failure input is recorded, never silently dropped.
    assert [s["content"] for s in inline] == ["one` b `half-open` more text`"]
    assert inline[-1]["unpaired"] is True
    assert any("unpaired backtick on line 1" in w for w in warnings)


# ---------------------------------------------------------------------------
# check_inline_span / check_fence_lines
# ---------------------------------------------------------------------------


def test_check_inline_span_missing_path_fails_and_existing_passes(cda):
    assert cda.check_inline_span({"content": "docs/does/not/exist.md"}) == [
        "inline path does not exist: docs/does/not/exist.md"
    ]
    assert cda.check_inline_span({"content": "README.md"}) == []


def test_check_inline_span_single_word_and_external_pass_through(cda):
    assert cda.check_inline_span({"content": "valid"}) == []
    assert cda.check_inline_span({"content": "external://github.com/anything/at/all"}) == []


def test_check_fence_lines_module_invocation_is_not_a_repo_path(cda):
    # `.venv/bin/python -m pkg.mod` must produce no candidate at all.
    assert (
        cda.check_fence_lines(
            [
                {
                    "kind": "fence",
                    "line_no": 1,
                    "content": ".venv/bin/python -m services.investigation_ui.app",
                }
            ]
        )
        == []
    )


def test_check_fence_lines_strips_cli_wrapper_then_checks_first_arg(cda):
    failing = cda.check_fence_lines(
        [{"kind": "fence", "line_no": 1, "content": "python3 tests/no/such_file.py"}]
    )
    assert failing == ["code block target does not exist: tests/no/such_file.py"]
    # An existing artéfact passes: the fixture generator is tracked.
    assert (
        cda.check_fence_lines(
            [
                {
                    "kind": "fence",
                    "line_no": 1,
                    "content": ".venv/bin/pytest tests/tools/test_check_docs_alignment.py",
                }
            ]
        )
        == []
    )


def test_check_fence_lines_skips_comments_prompt_and_flag_only_lines(cda):
    spans = [
        {"kind": "fence", "line_no": n, "content": line}
        for n, line in enumerate(
            ["# a comment", "$ .venv/bin/python docs/x.md", "  ", "-v"], start=1
        )
    ]
    assert cda.check_fence_lines(spans) == []


def test_check_fence_lines_unknown_command_prefix_yields_no_candidate(cda):
    assert (
        cda.check_fence_lines([{"kind": "fence", "line_no": 1, "content": "echo docs/nope.md"}])
        == []
    )


# ---------------------------------------------------------------------------
# check_document + main()
# ---------------------------------------------------------------------------


def test_check_document_flags_github_url_outside_the_documented_repo(cda, tmp_path):
    doc = _doc(
        tmp_path,
        text="See `https://github.com/someone-else/raucle` and `https://github.com/epic28-ltd/raucle-agent-assurance`.\n",
    )
    problems = cda.check_document(doc)
    assert any("someone-else/raucle" in p for p in problems)
    # The documented repo itself is allowed.
    assert (
        cda.check_document(
            _doc(
                tmp_path,
                name="ok.md",
                text="`https://github.com/epic28-ltd/raucle-agent-assurance`\n",
            )
        )
        == []
    )


def test_check_document_prefixes_failures_with_the_doc_name(cda, tmp_path):
    doc = _doc(tmp_path, name="role-x.md", text="`tests/no/such.py`\n")
    problems = cda.check_document(doc)
    assert problems == ["role-x.md: inline path does not exist: tests/no/such.py (line 1)"]


def test_main_passes_on_a_clean_roles_dir(cda, tmp_path):
    roles = tmp_path / "roles"
    roles.mkdir()
    for name in ("leaders.md", "architects.md", "engineers.md"):
        (roles / name).write_text(ROLES_MD)
    assert cda.main(["--roles-dir", str(roles)]) == 0


def test_main_fails_on_a_missing_role_document(cda, tmp_path):
    roles = tmp_path / "roles"
    roles.mkdir()
    (roles / "engineers.md").write_text("only one present\n")
    assert cda.main(["--roles-dir", str(roles)]) == 1


def test_main_fails_on_a_poisoned_role_document(cda, tmp_path):
    roles = tmp_path / "roles"
    roles.mkdir()
    for name in ("leaders.md", "architects.md", "engineers.md"):
        (roles / name).write_text(ROLES_MD)
    (roles / "zz-broken.md").write_text("```bash\npython3 tests/no/such_thing.py\n```\n")
    assert cda.main(["--roles-dir", str(roles)]) == 1
