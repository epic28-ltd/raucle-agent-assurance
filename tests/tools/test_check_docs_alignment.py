# SPDX-License-Identifier: Apache-2.0
"""OV-6 docs-alignment check tests: role documents reference only live artefacts."""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import textwrap

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "check_docs_alignment.py"
ROLES_DIR = REPO / "docs" / "assurance" / "roles"


def _run(*args):
    return subprocess.run(["python3", str(SCRIPT), *args], capture_output=True, text=True)


def test_all_role_documents_align():
    result = _run()
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS" in result.stdout


def test_missing_artefact_reference_fails():
    poisoned = ROLES_DIR / "zz-poisoned-check.md"
    poisoned.write_text(
        textwrap.dedent(
            """\
            # Poisoned check document
            See `docs/does/not/exist.md` for details.
            """
        )
    )
    try:
        result = _run()
        assert result.returncode == 1
        assert "docs/does/not/exist.md" in result.stdout
        assert result.stdout.count("FAIL") >= 1
    finally:
        poisoned.unlink()
    assert _run().returncode == 0, "doc set must be self-healing after the check"


def test_missing_role_document_fails():
    real = ROLES_DIR / "leaders.md"
    original = real.read_text()
    real.unlink()
    try:
        result = _run()
        assert result.returncode == 1
        assert "missing role document: leaders.md" in result.stdout
    finally:
        real.write_text(original)
    assert (ROLES_DIR / "leaders.md").read_text() == original
    assert _run().returncode == 0


def test_unpaired_backtick_is_a_named_failure():
    """OV-15: an unpaired backtick must fail visibly, never silently skip."""
    poisoned = ROLES_DIR / "zz-unpaired-tick.md"
    poisoned.write_text("Docs say `valid and then `docs/does/not/exist.md` for details.\n")
    try:
        result = _run()
        assert result.returncode == 1
        assert "unpaired backtick on line 1" in result.stdout
        # The inline path after the unpaired tick must still be caught
        # (the old text-global regex silently swallowed it).
        assert "docs/does/not/exist.md" in result.stdout
    finally:
        poisoned.unlink()
    assert _run().returncode == 0


def test_unclosed_fence_is_a_named_failure():
    poisoned = ROLES_DIR / "zz-unclosed-fence.md"
    poisoned.write_text(
        "```bash\n.venv/bin/python scripts/check_docs_alignment.py\n"
        # no closing fence
    )
    try:
        result = _run()
        assert result.returncode == 1
        assert "unclosed fence opened on line 1" in result.stdout
    finally:
        poisoned.unlink()
    assert _run().returncode == 0


def test_inline_refs_skipped_inside_bash_fence_but_fence_content_checked():
    poisoned = ROLES_DIR / "zz-fence-scope.md"
    poisoned.write_text(
        textwrap.dedent(
            """\
            # Fence scope check
            ```bash
            .venv/bin/python docs/does/not/exist.py
            ```
            """
        )
    )
    try:
        result = _run()
        assert result.returncode == 1
        assert "code block target does not exist: docs/does/not/exist.py" in result.stdout
    finally:
        poisoned.unlink()
    assert _run().returncode == 0


def test_non_bash_fence_language_is_named():
    poisoned = ROLES_DIR / "zz-non-bash-fence.md"
    poisoned.write_text("```\ndocs/does/not/exist.md\n```\n")
    try:
        result = _run()
        assert result.returncode == 1
        assert "no language tag" in result.stdout
    finally:
        poisoned.unlink()
    assert _run().returncode == 0


def test_parse_document_reports_every_inline_span():
    spec = importlib.util.spec_from_file_location("cda", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    cda = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cda)
    spans, warnings = cda.parse_document("a `one` b `two` c\nx `y\n")
    inline = [s for s in spans if s["kind"] == "inline"]
    assert [s["content"] for s in inline] == ["one", "two", "y"]
    assert any("unpaired backtick on line 2" in w for w in warnings)


def _load_module():
    spec = importlib.util.spec_from_file_location("check_docs_alignment", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _mod():
    if not hasattr(_load_module, "_cache"):
        _load_module._cache = _load_module()
    return _load_module._cache


def test_parse_document_pairs_inline_and_fence_spans():
    mod = _mod()
    text = textwrap.dedent(
        """
        prose `scripts/check_docs_alignment.py` inline.

        ```bash
        .venv/bin/python scripts/check_docs_alignment.py
        ```

        ```python
        print("not a bash fence")
        ```
        """
    )
    spans, warnings = mod.parse_document(text)
    kinds = [s["kind"] for s in spans]
    assert kinds.count("inline") >= 1
    assert kinds.count("fence") >= 1
    # the ```python fence is named as outside the checked set, not scanned
    assert warnings == ["non-bash fence (language 'python') opened on line 8"]


def test_check_inline_span_flags_missing_repo_path_and_skips_external():
    mod = _mod()
    assert mod.check_inline_span({"content": "docs/does/not/exist.md"}) == [
        "inline path does not exist: docs/does/not/exist.md"
    ]
    assert mod.check_inline_span({"content": "external://somewhere-else"}) == []
    assert mod.check_inline_span({"content": "README.md"}) == []


def test_check_fence_lines_strips_cli_wrappers_and_flags_missing_target():
    mod = _mod()
    fence = [{"content": ".venv/bin/python scripts/nope.py --flag"}]
    assert mod.check_fence_lines(fence) == ["code block target does not exist: scripts/nope.py"]
    # module invocation is not a repo path; prompts and comments are prose
    assert mod.check_fence_lines([{"content": ".venv/bin/python -m pytest"}]) == []
    assert mod.check_fence_lines([{"content": "# just a comment"}]) == []
    assert mod.check_fence_lines([{"content": "$ .venv/bin/pytest -q"}]) == []
    assert mod.check_fence_lines([{"content": ""}]) == []
    assert mod.check_fence_lines([{"content": ".venv/bin/ruff format"}]) == []


def test_check_document_names_external_github_links():
    mod = _mod()
    tmp = pathlib.Path(SCRIPT.parent)
    doc = tmp / "_test_external_link_alignment.md"
    try:
        doc.write_text("see `https://github.com/someone/else/wiki`\n")
        problems = mod.check_document(doc)
        assert any("_test_external_link_alignment.md: external URL" in p for p in problems)
    finally:
        doc.unlink()


def test_main_passes_on_synthetic_roles_dir(tmp_path):
    mod = _mod()
    for name in ("leaders.md", "architects.md", "engineers.md"):
        (tmp_path / name).write_text("see `README.md`\n")
    rc = mod.main(["--roles-dir", str(tmp_path)])
    assert rc == 0
