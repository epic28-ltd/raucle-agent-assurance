# SPDX-License-Identifier: Apache-2.0
"""Determinism, digest binding and unpinned-tool refusal tests for the evidence archive."""

from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]

RECORDED_UTC = "2026-11-26T00:00:00Z"
SOURCE_COMMIT = "a" * 40
IMAGE_REF = "docker.io/library/python:3.12-alpine"
IMAGE_DIGEST = "sha256:" + "b" * 64


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "evidence_archive", REPO / "tools" / "evidence_archive" / "archive.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_ea = _load_module()


def _write_fixture(base: pathlib.Path, name: str, content: bytes) -> pathlib.Path:
    path = base / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
    return path


def _valid_inputs(base: pathlib.Path) -> dict:
    sbom_path = _write_fixture(base, "scan/console.cdx.json", b'{"components": ["a", "b"]}\n')
    audit_path = _write_fixture(base, "scan/console-audit.json", b'{"dependencies": []}\n')
    _write_fixture(base, "provenance/provenance.txt", b"commit=" + SOURCE_COMMIT.encode() + b"\n")
    digest_a = _ea.sha256_bytes(sbom_path.read_bytes())
    digest_b = _ea.sha256_bytes(audit_path.read_bytes())
    return {
        "archive_id": "release-evidence",
        "release_tag": "v9.9.9-test",
        "source_commit_sha": SOURCE_COMMIT,
        "recorded_utc": RECORDED_UTC,
        "artifacts": [
            {
                "id": "console-sbom",
                "kind": "sbom",
                "path": "scan/console.cdx.json",
                "sha256": digest_a,
                "tools": [{"name": "syft", "version": "v1.57.2"}],
                "bindings": {
                    "component_name": "raucle-console",
                    "component_version": "0.1.0",
                    "component_sha256": "c" * 64,
                },
            },
            {
                "id": "console-audit",
                "kind": "vuln_report",
                "path": "scan/console-audit.json",
                "sha256": digest_b,
                "tools": [{"name": "pip-audit", "version": "2.10.1"}],
                "bindings": {"lockfile_sha256": "d" * 64},
            },
        ],
    }


def _build(inputs: dict, base: pathlib.Path, tmp_path: pathlib.Path, name: str) -> pathlib.Path:
    inputs_path = tmp_path / f"{name}-inputs.json"
    inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
    out = tmp_path / f"{name}-archive"
    digest = _ea.build_archive(inputs_path, base, out)
    assert digest
    return out


def test_same_inputs_produce_byte_identical_manifests(tmp_path):
    base = tmp_path / "base"
    second_base = tmp_path / "base-clone"
    inputs = _valid_inputs(base)
    for path in base.rglob("*"):
        if path.is_file():
            _write_fixture(second_base, path.relative_to(base), path.read_bytes())
    first = _build(inputs, base, tmp_path, "one")
    second = _build(inputs, second_base, tmp_path, "two")
    assert (first / _ea.MANIFEST_NAME).read_bytes() == (second / _ea.MANIFEST_NAME).read_bytes()
    sidecar_first = (first / _ea.DIGEST_SIDECAR_NAME).read_bytes()
    sidecar_second = (second / _ea.DIGEST_SIDECAR_NAME).read_bytes()
    assert sidecar_first == sidecar_second
    assert first.name != second.name
    manifest_text = (first / _ea.MANIFEST_NAME).read_text(encoding="utf-8")
    assert str(first) not in manifest_text and str(tmp_path) not in manifest_text
    for artifact in json.loads(manifest_text)["artifacts"]:
        assert (first / artifact["stored_as"]).read_bytes() == (
            second / artifact["stored_as"]
        ).read_bytes()


def test_manifest_records_canonical_form_and_bindings(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    inputs["artifacts"][0]["bindings"]["image_ref"] = IMAGE_REF
    inputs["artifacts"][0]["bindings"]["image_digest"] = IMAGE_DIGEST
    out = _build(inputs, base, tmp_path, "main")
    manifest = json.loads((out / _ea.MANIFEST_NAME).read_text(encoding="utf-8"))
    raw = (out / _ea.MANIFEST_NAME).read_bytes().decode("utf-8")
    assert raw.endswith("\n")
    canon = _ea.canonical_json_bytes(manifest)
    assert canon == (out / _ea.MANIFEST_NAME).read_bytes()
    assert json.loads(canon.decode()) == json.loads(raw)
    assert manifest["archive_schema"] == _ea.ARCHIVE_SCHEMA
    assert manifest["source_commit_sha"] == SOURCE_COMMIT
    assert manifest["release_tag"] == "v9.9.9-test"
    assert manifest["recorded_utc"] == RECORDED_UTC
    assert manifest["generator"] == {"name": "evidence_archive", "version": "1.0.0"}
    assert manifest["counts"] == {"artifacts": 2}
    entries = {entry["id"]: entry for entry in manifest["artifacts"]}
    assert entries["console-sbom"]["bindings"]["component_sha256"] == "c" * 64
    assert entries["console-sbom"]["bindings"]["image_digest"] == IMAGE_DIGEST
    assert entries["console-sbom"]["bindings"]["image_ref"] == IMAGE_REF
    assert entries["console-sbom"]["tools"] == [{"name": "syft", "version": "v1.57.2"}]
    assert entries["console-audit"]["bindings"]["lockfile_sha256"] == "d" * 64
    stored = out / entries["console-sbom"]["stored_as"]
    assert stored.read_bytes() == (base / "scan/console.cdx.json").read_bytes()
    sidecar = (out / _ea.DIGEST_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    assert sidecar == _ea.sha256_bytes((out / _ea.MANIFEST_NAME).read_bytes())


def test_tampered_artifact_fails_with_named_error(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    artifact = dict(inputs["artifacts"][0])
    tampered = dict(artifact, sha256=_ea.sha256_bytes(b"TAMPERED\n"))
    inputs["artifacts"] = [tampered, inputs["artifacts"][1]]
    _write_fixture(base, artifact["path"], b"TAMPERED-CONTENT\n")
    with pytest.raises(_ea.DigestMismatchError) as raised:
        _build(inputs, base, tmp_path, "tampered")
    assert "tampered" in str(raised.value).lower()


def test_declared_digest_must_match_real_file_bytes(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    wrong = dict(inputs["artifacts"][0], sha256="e" * 64)
    inputs["artifacts"] = [wrong, inputs["artifacts"][1]]
    with pytest.raises(_ea.DigestMismatchError):
        _build(inputs, base, tmp_path, "misdeclared")


def test_missing_digest_fails_with_missing_digest_error(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    stripped = {k: v for k, v in inputs["artifacts"][0].items() if k != "sha256"}
    inputs["artifacts"] = [stripped, inputs["artifacts"][1]]
    with pytest.raises(_ea.MissingDigestError):
        _ea.parse_inputs(inputs)


def test_sbom_without_any_digest_binding_is_refused(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    unbound = dict(inputs["artifacts"][0], bindings={})
    inputs["artifacts"] = [unbound, inputs["artifacts"][1]]
    with pytest.raises(_ea.MissingBindingError) as raised:
        _ea.parse_inputs(inputs)
    assert "no immutable digest binding" in str(raised.value)


def test_vuln_report_without_any_digest_binding_is_refused(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    unbound = dict(inputs["artifacts"][1], bindings={})
    inputs["artifacts"] = [inputs["artifacts"][0], unbound]
    with pytest.raises(_ea.MissingBindingError):
        _ea.parse_inputs(inputs)


def test_image_binding_requires_ref_and_digest_shape(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    bad_digest = {
        "component_name": "raucle-console",
        "component_version": "0.1.0",
        "image_ref": IMAGE_REF,
    }
    with pytest.raises(_ea.MissingBindingError):
        _ea.parse_inputs(
            {**inputs, "artifacts": [dict(inputs["artifacts"][0], bindings=bad_digest)]}
        )


def test_malformed_image_digest_is_named(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    bindings = {
        "component_name": "raucle-console",
        "component_version": "0.1.0",
        "image_ref": IMAGE_REF,
        "image_digest": "latest",
    }
    with pytest.raises(_ea.DigestFormatError) as raised:
        _ea.parse_inputs({**inputs, "artifacts": [dict(inputs["artifacts"][0], bindings=bindings)]})
    assert "image_digest" in str(raised.value)


@pytest.mark.parametrize("unpinned", ["latest", "unpinned", "", "main", "rolling"])
def test_unpinned_tool_versions_are_refused(tmp_path, unpinned):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    unpinned_run = {
        "id": "console-sbom",
        "kind": "sbom",
        "path": "scan/console.cdx.json",
        "sha256": inputs["artifacts"][0]["sha256"],
        "tools": [{"name": "syft", "version": unpinned}],
        "bindings": {"component_sha256": "c" * 64},
    }
    with pytest.raises(_ea.UnpinnedToolError) as raised:
        _ea.parse_inputs({**inputs, "artifacts": [unpinned_run, inputs["artifacts"][1]]})
    assert str(unpinned) in str(raised.value)


def test_digitless_tool_version_is_refused(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    floating = dict(inputs["artifacts"][0], tools=[{"name": "syft", "version": "nightly"}])
    with pytest.raises(_ea.UnpinnedToolError):
        _ea.parse_inputs({**inputs, "artifacts": [floating, inputs["artifacts"][1]]})


def test_sbom_or_vuln_report_without_tool_run_is_refused(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    no_tools = dict(inputs["artifacts"][1])
    del no_tools["tools"]
    with pytest.raises(_ea.UnpinnedToolError) as raised:
        _ea.parse_inputs({**inputs, "artifacts": [inputs["artifacts"][0], no_tools]})
    assert "no tool run" in str(raised.value)


def test_missing_commit_sha_is_refused_with_binding_error(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    for missing in (None, "", "HEAD", "f" * 39):
        stripped = dict(inputs)
        if missing is None:
            del stripped["source_commit_sha"]
        else:
            stripped["source_commit_sha"] = missing
        with pytest.raises(_ea.MissingBindingError):
            _ea.parse_inputs(stripped)


def test_missing_source_file_is_refused(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    (base / "scan/console.cdx.json").unlink()
    with pytest.raises(_ea.InputNotFoundError):
        _build(inputs, base, tmp_path, "missing-source")


def test_duplicate_artifact_id_is_refused(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    inputs["artifacts"] = [
        inputs["artifacts"][0],
        dict(inputs["artifacts"][1], id=inputs["artifacts"][0]["id"]),
    ]
    with pytest.raises(_ea.DuplicateArtifactError):
        _ea.parse_inputs(inputs)


def test_provenance_artifact_needs_no_tool_run_but_still_needs_digest(tmp_path):
    base = tmp_path / "base"
    provenance = _write_fixture(base, "meta/provenance.txt", b"release_tag=v1\n")
    inputs = {
        "archive_id": "provenance-only",
        "release_tag": "v1",
        "source_commit_sha": "5" * 40,
        "artifacts": [
            {
                "id": "provenance-record",
                "kind": "provenance",
                "path": "meta/provenance.txt",
                "sha256": _ea.sha256_bytes(provenance.read_bytes()),
            }
        ],
    }
    out = _build(inputs, base, tmp_path, "prov")
    manifest = json.loads((out / _ea.MANIFEST_NAME).read_text(encoding="utf-8"))
    assert manifest["artifacts"][0]["kind"] == "provenance"


def test_verify_passes_on_a_built_archive_and_catches_tampering(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    out = _build(inputs, base, tmp_path, "verify")
    digest = _ea.verify_archive(out)
    assert digest == (out / _ea.DIGEST_SIDECAR_NAME).read_text(encoding="utf-8").strip()
    entries = {
        entry["id"]: entry
        for entry in json.loads((out / _ea.MANIFEST_NAME).read_text(encoding="utf-8"))["artifacts"]
    }
    target = out / entries["console-sbom"]["stored_as"]
    target.write_bytes(b"corrupted after build\n")
    with pytest.raises(_ea.DigestMismatchError) as raised:
        _ea.verify_archive(out)
    assert "archive artifact console-sbom" in str(raised.value)


def test_cli_build_and_verify_and_named_error_exit(tmp_path):
    base = tmp_path / "base"
    inputs = _valid_inputs(base)
    inputs_path = tmp_path / "cli-inputs.json"
    inputs_path.write_text(json.dumps(inputs), encoding="utf-8")
    out = tmp_path / "cli-archive"
    env = {k: v for k, v in os.environ.items() if k.lower() != "pythonpath"}
    module = REPO / "tools" / "evidence_archive" / "archive.py"
    built = subprocess.run(
        [
            sys.executable,
            str(module),
            "build",
            "--inputs",
            str(inputs_path),
            "--base",
            str(base),
            "--out",
            str(out),
        ],
        capture_output=True,
        text=True,
        env={**env, "PYTHONPATH": ""},
    )
    assert built.returncode == 0, built.stderr
    assert out.joinpath(_ea.MANIFEST_NAME).is_file()
    verified = subprocess.run(
        [sys.executable, str(module), "verify", str(out)],
        capture_output=True,
        text=True,
        env={**env, "PYTHONPATH": ""},
    )
    assert verified.returncode == 0, verified.stderr
    (tmp_path / "broken-inputs.json").write_text(
        json.dumps({**inputs, "source_commit_sha": "HEAD"}), encoding="utf-8"
    )
    refused = subprocess.run(
        [
            sys.executable,
            str(module),
            "build",
            "--inputs",
            str(tmp_path / "broken-inputs.json"),
            "--base",
            str(base),
            "--out",
            str(tmp_path / "refused-archive"),
        ],
        capture_output=True,
        text=True,
        env={**env, "PYTHONPATH": ""},
    )
    assert refused.returncode == 2
    assert "MissingBindingError" in refused.stderr
