# SPDX-License-Identifier: Apache-2.0
"""Guards for the durable evidence archive committed under docs/security/evidence.

The archive home is data plus docs: these tests hold the committed artifacts
against the archive tooling's own verify (digest sidecar, artifact digests),
hold every manifest against its binding contract, and reconcile the index
page and the retention policy with what is actually committed, so the page
cannot drift from the bytes without a failing test.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[2]
EVIDENCE = REPO / "docs" / "security" / "evidence"
MANIFEST_NAME = "MANIFEST.json"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "evidence_archive_home_check", REPO / "tools" / "evidence_archive" / "archive.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_ea = _load_module()


def _committed_manifests() -> list[pathlib.Path]:
    return sorted(EVIDENCE.glob(f"*/{MANIFEST_NAME}"))


def test_every_committed_evidence_archive_verifies_with_the_archive_tooling():
    manifests = _committed_manifests()
    assert manifests, "the durable evidence archive home has no committed archives"
    for manifest in manifests:
        directory = manifest.parent
        digest = _ea.verify_archive(directory)
        sidecar = (directory / f"{MANIFEST_NAME}.sha256").read_text().strip()
        recomputed = hashlib.sha256(manifest.read_bytes()).hexdigest()
        assert digest == sidecar == recomputed


def test_every_committed_archive_binds_release_tag_and_source_commit():
    for manifest in _committed_manifests():
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        assert payload["release_tag"], manifest
        assert re.match(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$", payload["source_commit_sha"]), manifest
        assert payload["generator"] == {"name": "evidence_archive", "version": "1.0.0"}


def test_every_committed_sbom_entry_declares_pinned_tool_run():
    for manifest in _committed_manifests():
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        entries = [
            entry for entry in payload["artifacts"] if entry["kind"] in {"sbom", "vuln_report"}
        ]
        assert entries, "SBOM or vulnerability reports are the reason this archive exists"
        for entry in entries:
            tools = entry.get("tools") or []
            assert tools, f"{entry['id']} records no pinned tool run"
            for tool in tools:
                assert re.search(r"\d", tool["version"]), (entry["id"], tool)


def test_index_page_records_the_manifest_and_sbom_digests_of_every_archive():
    page = (EVIDENCE / "ARCHIVE-INDEX.md").read_text(encoding="utf-8")
    for manifest in _committed_manifests():
        payload = json.loads(manifest.read_text(encoding="utf-8"))
        sidecar = (manifest.parent / f"{MANIFEST_NAME}.sha256").read_text().strip()
        assert sidecar in page, f"manifest digest of {payload['archive_id']} missing from the index"
        assert payload["source_commit_sha"] in page, (
            f"source commit of {payload['archive_id']} missing from the index"
        )
        for entry in payload["artifacts"]:
            if entry["kind"] == "sbom":
                assert entry["sha256"] in page, (
                    f"SBOM digest of {entry['id']} missing from the index"
                )


def test_retention_policy_states_the_decided_minimum_review_and_ci_relationship():
    policy = (EVIDENCE / "RETENTION.md").read_text(encoding="utf-8")
    assert "12 months" in policy
    assert "Monthly review" in policy
    assert "supplements the CI artifacts" in policy
