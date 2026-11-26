#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Deterministic, digest-bound evidence archive generator.

Builds an evidence archive directory from a declared inputs file: every
SBOM, vulnerability report, component and provenance record is copied
verbatim, its SHA-256 digest is recomputed and compared against the
declared digest, and the whole set is bound to immutable artifact
identities (commit SHA, component digest, image digest) in a canonical
MANIFEST.json with a MANIFEST.json.sha256 sidecar.

Fail-closed contract, enforced with named errors:

- every artifact MUST declare a SHA-256 digest and the copied bytes MUST
  match it (a tampered or missing-digest artifact fails the build);
- SBOM and vulnerability reports MUST bind to at least one immutable
  digest identity (component, lockfile, requirements or image digest),
  and image bindings MUST carry a resolved ``sha256:<hex>`` image ref;
- SBOM and vulnerability reports MUST record a pinned tool run: at least
  one tool whose version is exact and unpinned placeholders ("latest",
  "unpinned", empty) are refused.

The same inputs always produce a byte-identical MANIFEST.json: the
manifest is sorted canonical JSON, no timestamps are generated from the
wall clock (only a provided ``recorded_utc`` is carried verbatim), and
archive layout paths are derived from declared artifact ids only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

GENERATOR_NAME = "evidence_archive"
GENERATOR_VERSION = "1.0.0"
ARCHIVE_SCHEMA = "raucle-agent-assurance/evidence-archive@v1"
MANIFEST_NAME = "MANIFEST.json"
DIGEST_SIDECAR_NAME = "MANIFEST.json.sha256"
ARTIFACTS_SUBDIR = "artifacts"

ARCHIVE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
ARTIFACT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
IMAGE_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RECORDED_UTC_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
BINDING_VALUE_KEYS = frozenset(
    {
        "component_name",
        "component_version",
        "component_sha256",
        "image_ref",
        "image_digest",
        "lockfile_sha256",
        "requirements_sha256",
        "release_tag",
    }
)
DIGEST_BINDING_KEYS = frozenset(
    {"component_sha256", "image_digest", "lockfile_sha256", "requirements_sha256"}
)
TOOL_REQUIRED_KINDS = frozenset({"sbom", "vuln_report"})
# A version is pinned when it names an exact release; these placeholders
# and digit-less values describe a moving target and are refused.
UNPINNED_VERSION_VALUES = frozenset({"latest", "unpinned", "head", "main", "master", "dev"})
DIGEST_BINDING_REQUIRED_KINDS = frozenset({"sbom", "vuln_report"})


class ArchiveInputsError(Exception):
    """Base class: archive inputs are refused with a named, actionable error."""


class InvalidInputError(ArchiveInputsError):
    """Inputs are structurally invalid (wrong type, bad id, bad timestamp)."""


class InputNotFoundError(ArchiveInputsError):
    """A declared artifact source file does not exist under the base directory."""


class DigestFormatError(ArchiveInputsError):
    """A digest value is present but malformed (not a lowercase sha256 hex)."""


class MissingDigestError(ArchiveInputsError):
    """An artifact declares no sha256 digest; the archive refuses to build."""


class DigestMismatchError(ArchiveInputsError):
    """Artifact bytes do not hash to their declared digest (tampered artifact)."""


class MissingBindingError(ArchiveInputsError):
    """An artifact carries no immutable digest binding for its kind."""


class UnpinnedToolError(ArchiveInputsError):
    """An SBOM or vulnerability report was produced by an unpinned tool run."""


class DuplicateArtifactError(ArchiveInputsError):
    """Two artifacts declare the same id."""


def canonical_json_bytes(payload: object) -> bytes:
    """Serialise to the archive's canonical form: sorted, compact, one trailing newline."""
    return (
        json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _require_string(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidInputError(f"{where} must be a non-empty string")
    return value


def _validate_digest(value: object, where: str, error: type[ArchiveInputsError]) -> str:
    if not isinstance(value, str) or not value:
        raise error(f"{where} declares no sha256 digest")
    if not SHA256_RE.match(value):
        raise DigestFormatError(
            f"{where} digest is malformed: expected 64 lowercase hex characters"
        )
    return value


def _validate_tools(tools: object, where: str) -> list[dict[str, str]]:
    if not isinstance(tools, list) or len(tools) == 0:
        raise UnpinnedToolError(
            f"{where} records no tool run: every SBOM or vulnerability report "
            "must carry at least one pinned tool"
        )
    validated: list[dict[str, str]] = []
    for tool in tools:
        if not isinstance(tool, dict) or set(tool) != {"name", "version"}:
            raise InvalidInputError(
                f"{where} tool run must be an object with exactly name and version"
            )
        name = _require_string(tool["name"], f"{where} tool name")
        version = tool["version"]
        if not isinstance(version, str) or not version:
            raise UnpinnedToolError(f"{where} tool {name} has no pinned version")
        if version.lower() in UNPINNED_VERSION_VALUES or not re.search(r"\d", version):
            raise UnpinnedToolError(
                f"{where} tool {name} version {version!r} is not an exact pinned version; "
                "the archive refuses an unpinned tool run"
            )
        validated.append({"name": name, "version": version})
    validated.sort(key=lambda item: (item["name"], item["version"]))
    return validated


def _validate_bindings(bindings: object, kind: str, where: str) -> dict[str, str]:
    if bindings is None:
        bindings = {}
    if not isinstance(bindings, dict):
        raise InvalidInputError(f"{where} bindings must be an object")
    unknown = set(bindings) - BINDING_VALUE_KEYS
    if unknown:
        raise InvalidInputError(f"{where} declares unknown binding keys: {sorted(unknown)}")
    for key in ("component_sha256", "lockfile_sha256", "requirements_sha256"):
        if key in bindings:
            _validate_digest(bindings[key], f"{where} binding {key}", DigestFormatError)
    if "component_name" in bindings:
        _require_string(bindings["component_name"], f"{where} binding component_name")
        if (
            not isinstance(bindings.get("component_version"), str)
            or not bindings["component_version"]
        ):
            raise InvalidInputError(
                f"{where} binding component_name requires component_version alongside it"
            )
    if "component_version" in bindings and "component_name" not in bindings:
        raise InvalidInputError(f"{where} binding component_version requires component_name")
    if "image_digest" in bindings:
        if not isinstance(bindings["image_digest"], str) or not IMAGE_DIGEST_RE.match(
            bindings["image_digest"]
        ):
            raise DigestFormatError(
                f"{where} binding image_digest must be an immutable digest reference sha256:<64 hex>"
            )
        if "image_ref" not in bindings:
            raise MissingBindingError(
                f"{where} binding image_digest requires image_ref alongside it"
            )
    if "image_ref" in bindings:
        _require_string(bindings["image_ref"], f"{where} binding image_ref")
    if kind in DIGEST_BINDING_REQUIRED_KINDS and not DIGEST_BINDING_KEYS.intersection(bindings):
        raise MissingBindingError(
            f"{where} is a {kind} artifact with no immutable digest binding; it must bind to a "
            "component_sha256, lockfile_sha256, requirements_sha256 or image_digest"
        )
    return {key: bindings[key] for key in sorted(bindings)}


def _validate_artifact(record: object, where: str) -> dict[str, object]:
    if not isinstance(record, dict):
        raise InvalidInputError(f"{where} must be an object")
    unknown = set(record) - {
        "id",
        "kind",
        "path",
        "sha256",
        "bindings",
        "tools",
    }
    if unknown:
        raise InvalidInputError(f"{where} declares unknown keys: {sorted(unknown)}")
    artifact_id = _require_string(record.get("id"), f"{where} id")
    if not ARTIFACT_ID_RE.match(artifact_id):
        raise InvalidInputError(f"{where} id {artifact_id!r} must match [a-z0-9][a-z0-9-]{{0,63}}")
    kind = _require_string(record.get("kind"), f"{where} kind")
    if kind not in TOOL_REQUIRED_KINDS | {"component", "provenance"}:
        raise InvalidInputError(
            f"{where} kind {kind!r} is unknown; expected one of sbom, vuln_report, component, provenance"
        )
    path = _require_string(record.get("path"), f"{where} path")
    if path.startswith("/") or Path(*Path(path).parts[:1]).name == "..":
        raise InvalidInputError(f"{where} path must be a relative path under the base directory")
    if ".." in Path(path).parts:
        raise InvalidInputError(f"{where} path must not traverse above the base directory")
    declared_digest = _validate_digest(record.get("sha256"), where, MissingDigestError)
    tools = _validate_tools(record.get("tools"), where) if kind in TOOL_REQUIRED_KINDS else []
    bindings = _validate_bindings(record.get("bindings"), kind, where)
    return {
        "id": artifact_id,
        "kind": kind,
        "path": path,
        "sha256": declared_digest,
        "tools": tools,
        "bindings": bindings,
        "where": where,
    }


def parse_inputs(inputs: object) -> dict[str, object]:
    """Validate archive inputs and return the normalised build plan."""
    if not isinstance(inputs, dict):
        raise InvalidInputError("inputs must be a JSON object")
    unknown = set(inputs) - {
        "archive_id",
        "release_tag",
        "source_commit_sha",
        "recorded_utc",
        "artifacts",
    }
    if unknown:
        raise InvalidInputError(f"inputs declare unknown keys: {sorted(unknown)}")
    archive_id = _require_string(inputs.get("archive_id"), "archive_id")
    if not ARCHIVE_ID_RE.match(archive_id):
        raise InvalidInputError(f"archive_id {archive_id!r} must match [a-z0-9][a-z0-9-]{{0,63}}")
    release_tag = inputs.get("release_tag")
    if release_tag is None:
        release_tag = "unreleased"
    if not isinstance(release_tag, str) or not release_tag:
        raise InvalidInputError("release_tag must be a non-empty string")
    commit = inputs.get("source_commit_sha")
    if isinstance(commit, str):
        commit = commit.strip().lower()
    if not isinstance(commit, str) or not COMMIT_SHA_RE.match(commit):
        raise MissingBindingError(
            "source_commit_sha is missing or malformed; the manifest must bind to the exact "
            "commit that produced the evidence"
        )
    recorded_utc = inputs.get("recorded_utc")
    if recorded_utc is not None and (
        not isinstance(recorded_utc, str) or not RECORDED_UTC_RE.match(recorded_utc)
    ):
        raise InvalidInputError(
            "recorded_utc must be an ISO-8601 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ); the "
            "generator never invents a timestamp from the wall clock"
        )
    raw_artifacts = inputs.get("artifacts")
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) == 0:
        raise InvalidInputError("artifacts must be a non-empty list")
    seen: set[str] = set()
    artifacts: list[dict[str, object]] = []
    for index, record in enumerate(raw_artifacts):
        where = f"artifacts[{index}]"
        artifact = _validate_artifact(record, where)
        if artifact["id"] in seen:
            raise DuplicateArtifactError(f"artifact id {artifact['id']} declared twice")
        seen.add(artifact["id"])
        artifacts.append(artifact)
    return {
        "archive_id": archive_id,
        "release_tag": release_tag,
        "source_commit_sha": commit,
        "recorded_utc": recorded_utc,
        "artifacts": artifacts,
    }


def _read_base_bytes(base: Path, plan: dict[str, object]) -> dict[str, bytes]:
    sources: dict[str, bytes] = {}
    for artifact in plan["artifacts"]:
        where = str(artifact["where"])
        source = base / artifact["path"]
        if not source.is_file():
            raise InputNotFoundError(f"{where} path {artifact['path']} does not exist under {base}")
        sources[artifact["id"]] = source.read_bytes()
    return sources


def _stored_as(artifact_id: str, path: Path) -> str:
    return f"{ARTIFACTS_SUBDIR}/{artifact_id}/{path.name}"


def build_manifest(plan: dict[str, object], sources: dict[str, bytes]) -> dict[str, object]:
    """Assemble the manifest payload, failing closed on digest and binding rules."""
    entries: list[dict[str, object]] = []
    for artifact in plan["artifacts"]:
        content = sources[str(artifact["id"])]
        actual = sha256_bytes(content)
        where = str(artifact["where"])
        if actual != artifact["sha256"]:
            raise DigestMismatchError(
                f"{where} ({artifact['id']}, {artifact['path']}) hashes to {actual} but declares "
                f"{artifact['sha256']}; a tampered or stale artifact must fail the manifest build"
            )
        stored_as = _stored_as(str(artifact["id"]), Path(str(artifact["path"])))
        entry: dict[str, object] = {
            "id": artifact["id"],
            "kind": artifact["kind"],
            "path": artifact["path"],
            "stored_as": stored_as,
            "sha256": actual,
            "bytes": len(content),
            "bindings": artifact["bindings"],
        }
        if artifact["tools"]:
            entry["tools"] = artifact["tools"]
        entries.append(entry)
    entries.sort(key=lambda entry: str(entry["id"]))
    manifest: dict[str, object] = {
        "archive_id": plan["archive_id"],
        "archive_schema": ARCHIVE_SCHEMA,
        "generator": {"name": GENERATOR_NAME, "version": GENERATOR_VERSION},
        "source_commit_sha": plan["source_commit_sha"],
        "release_tag": plan["release_tag"],
        "artifacts": entries,
        "counts": {"artifacts": len(entries)},
    }
    if plan.get("recorded_utc"):
        manifest["recorded_utc"] = plan["recorded_utc"]
    return manifest


def build_archive(inputs_path: Path, base: Path, out: Path) -> str:
    """Build the archive; return the manifest digest. Errors are named and fatal."""
    if out.exists():
        raise InvalidInputError(
            f"output directory {out} already exists; the archive must be built into a fresh "
            "directory so an existing archive is never silently overwritten"
        )
    inputs = json.loads(inputs_path.read_text(encoding="utf-8"))
    plan = parse_inputs(inputs)
    sources = _read_base_bytes(base, plan)
    manifest = build_manifest(plan, sources)
    manifest_bytes = canonical_json_bytes(manifest)
    manifest_digest = sha256_bytes(manifest_bytes)
    out.mkdir(parents=True)
    for artifact in plan["artifacts"]:
        destination = out / _stored_as(str(artifact["id"]), Path(str(artifact["path"])))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(sources[str(artifact["id"])])
    (out / MANIFEST_NAME).write_bytes(manifest_bytes)
    (out / DIGEST_SIDECAR_NAME).write_bytes(f"{manifest_digest}\n".encode())
    return manifest_digest


def verify_archive(archive_dir: Path) -> str:
    """Re-verify a built archive; return the manifest digest or raise a named error."""
    manifest_path = archive_dir / MANIFEST_NAME
    sidecar_path = archive_dir / DIGEST_SIDECAR_NAME
    if not manifest_path.is_file() or not sidecar_path.is_file():
        raise InvalidInputError(f"{archive_dir} is not a built evidence archive")
    manifest_bytes = manifest_path.read_bytes()
    declared = sha256_bytes(manifest_bytes)
    recorded = sidecar_path.read_text(encoding="utf-8").strip()
    if recorded != declared:
        raise DigestMismatchError(
            f"MANIFEST.json hashes to {declared} but {DIGEST_SIDECAR_NAME} records {recorded}"
        )
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    for entry in manifest["artifacts"]:
        artifact_path = archive_dir / str(entry["stored_as"])
        if not artifact_path.is_file():
            raise InputNotFoundError(
                f"archive artifact {entry['id']} ({entry['stored_as']}) is missing from the archive"
            )
        actual = sha256_bytes(artifact_path.read_bytes())
        if actual != entry["sha256"]:
            raise DigestMismatchError(
                f"archive artifact {entry['id']} hashes to {actual} but the manifest records "
                f"{entry['sha256']}"
            )
    return declared


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build", help="build a digest-bound evidence archive")
    build.add_argument("--inputs", required=True, type=Path)
    build.add_argument("--base", default=".", type=Path)
    build.add_argument("--out", required=True, type=Path)
    verify = subparsers.add_parser("verify", help="re-verify a built evidence archive")
    verify.add_argument("archive", type=Path)
    args = parser.parse_args(argv)
    if args.command == "build":
        digest = build_archive(args.inputs, args.base, args.out)
        print(f"{MANIFEST_NAME} sha256 {digest}")
        return 0
    digest = verify_archive(args.archive)
    print(f"{MANIFEST_NAME} sha256 {digest} verified")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ArchiveInputsError as error:
        print(f"evidence_archive: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(2)
