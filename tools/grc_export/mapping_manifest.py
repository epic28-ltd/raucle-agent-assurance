# SPDX-License-Identifier: Apache-2.0
"""Regulatory mapping manifest export (issue 113: ISO 42001 / NIST AI RMF / EU AI Act evidence mappings).

Emits a versioned, deterministic ``regulatory_mapping_manifest/v1`` JSON
manifest over the governance crosswalk's ISO 42001, NIST AI RMF and EU AI Act
rows - the frameworks whose rows carry the evidence-mapping metadata
(``disposition``, ``owner``, ``evidence_freshness``,
``system_version_scope``, ``verification_status``). The manifest mirrors the
evidence-archive discipline (tools/evidence_archive): deterministic canonical
JSON, a per-row sha256 digest over the row's exact source content, and a
table digest over the ordered rows - so any tampering with, or drift of, a
mapping row is detectable by re-running the export.

Digest contract (OV-1 pattern, same as the GRC evidence graph):
- ``source_row_sha256`` = sha256 over the canonical JSON of the entire source
  crosswalk row (every field, including basis/unsat_reason text). Computed
  from the row as loaded; never from a projection.
- ``table_sha256`` = sha256 over the canonical JSON of the ordered manifest
  row list. Digest binding: the table over itself.
- ``manifest_content_sha256`` is added after the digest, outside it.

Honesty contract: the manifest asserts no certification, no regulatory
conformity, no independent audit, and no warranty of any kind. EU AI Act
applicability determinations are legal review inputs, not determinations.
Owner slots are pending assignments written as ``owner-pending Craig``.
Determinism contract: the same crosswalk bytes produce byte-identical
manifests (sorted keys, stable row order, no wall-clock data).
"""

from __future__ import annotations

import hashlib
import json

MANIFEST_KIND = "regulatory_mapping_manifest"
MANIFEST_SCHEMA_VERSION = 1

FRAMEWORKS = ("EU AI Act", "ISO 42001", "NIST AI RMF")

DISPOSITIONS = ("gap", "mapped", "not-applicable")
VERIFICATION_STATUSES = (
    "independent offline verification (verifier / red-run suites re-execute the control)",
    "engineering-authored only (documented and CI-tested in-repo; not independently re-verified offline)",
)
OWNER_PENDING = "owner-pending Craig"

METADATA_FIELDS = (
    "applicability_status",
    "disposition",
    "evidence_artifact",
    "evidence_freshness",
    "owner",
    "system_version_scope",
    "verification_status",
)

GUARD = (
    "This manifest digests the regulatory evidence mappings of the raucle-agent-assurance"
    " governance crosswalk (ISO/IEC 42001, NIST AI RMF, EU AI Act). Each row cites specific"
    " repository artifacts or states an explicit gap, with evidence freshness, an owner slot"
    " (owner-pending Craig), system and version scope, and independent-verification status."
    " This manifest is an evidence mapping: it is NOT certification, NOT regulatory conformity"
    " and NOT an independent audit, and it asserts no compliance of any kind. Applicability"
    " determinations for EU AI Act obligations are legal review inputs, not determinations."
    " Owner slots are pending assignments, never assertions that an owner is in place."
)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj: object) -> str:
    """Deterministic canonical form: sorted keys, no whitespace padding."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class ExportError(ValueError):
    """Named, user-legible failure; nothing is silently dropped or repaired."""


def _project_row(row: dict) -> dict:
    """The manifest's per-row projection: identity + every metadata field verbatim."""
    out: dict = {
        "control_id": row["control_id"],
        "framework": row["framework"],
        "status": row["status"],
    }
    for field in METADATA_FIELDS:
        if field in row:
            out[field] = row[field]
    return out


def build_manifest(crosswalk: dict, crosswalk_bytes: bytes | None = None) -> dict:
    """Assemble the manifest payload, failing closed on honesty rules.

    ``crosswalk_bytes`` (optional) binds the manifest to the exact crosswalk
    file bytes; when omitted, the canonical JSON of the loaded crosswalk is
    digested instead so the function stays pure over the parsed dict.
    """
    rows = crosswalk.get("rows")
    if not isinstance(rows, list) or not rows:
        raise ExportError("crosswalk has no rows")

    selected: list[tuple[dict, dict]] = []
    for row in rows:
        if row.get("framework") in FRAMEWORKS:
            selected.append((row, _project_row(row)))
    if not selected:
        raise ExportError(f"crosswalk has no rows for frameworks {FRAMEWORKS}")

    # sorted stable order: framework then control id (determinism contract)
    selected.sort(key=lambda pair: (pair[0]["framework"], pair[0]["control_id"]))

    manifest_rows: list[dict] = []
    for source_row, projection in selected:
        entry = dict(projection)
        entry["source_row_sha256"] = "sha256:" + _sha256_hex(canonical_json(source_row).encode())
        manifest_rows.append(entry)

    for row, entry in zip((s for s, _ in selected), manifest_rows, strict=True):
        status = row.get("status")
        disposition = entry.get("disposition")
        if disposition not in DISPOSITIONS:
            raise ExportError(
                f"{row['framework']}:{row['control_id']}: disposition {disposition!r} not one of {DISPOSITIONS}"
            )
        if status in ("SUPPORTED", "PARTIAL"):
            if disposition != "mapped":
                raise ExportError(
                    f"{row['framework']}:{row['control_id']}: {status} rows must be disposition 'mapped'"
                )
            if not entry.get("evidence_artifact") or not entry.get("evidence_freshness"):
                raise ExportError(
                    f"{row['framework']}:{row['control_id']}: mapped rows must cite an artifact and freshness"
                )
        elif status == "UNSUPPORTED":
            if disposition == "mapped":
                raise ExportError(
                    f"{row['framework']}:{row['control_id']}: UNSUPPORTED rows cannot be disposition 'mapped'"
                )
            if entry.get("evidence_artifact"):
                raise ExportError(
                    f"{row['framework']}:{row['control_id']}: gap rows must not cite an artifact"
                )
        else:
            raise ExportError(
                f"{row['framework']}:{row['control_id']}: unknown crosswalk status {status!r}"
            )
        if entry.get("owner") != OWNER_PENDING:
            raise ExportError(
                f"{row['framework']}:{row['control_id']}: owner slot must be {OWNER_PENDING!r}"
            )
        verification = entry.get("verification_status")
        if verification not in VERIFICATION_STATUSES:
            raise ExportError(
                f"{row['framework']}:{row['control_id']}: verification_status {verification!r} outside the vocabulary"
            )
        if row["framework"] == "EU AI Act" and "applicability_status" not in entry:
            raise ExportError(
                f"EU AI Act:{row['control_id']}: rows must carry the legal-review-input applicability_status"
            )

    counts: list[dict] = []
    for framework in FRAMEWORKS:
        fw_rows = [e for e in manifest_rows if e["framework"] == framework]
        counts.append(
            {
                "framework": framework,
                "rows": len(fw_rows),
                "supported": sum(1 for e in fw_rows if e["status"] == "SUPPORTED"),
                "partial": sum(1 for e in fw_rows if e["status"] == "PARTIAL"),
                "unsupported": sum(1 for e in fw_rows if e["status"] == "UNSUPPORTED"),
            }
        )

    manifest: dict = {
        "kind": MANIFEST_KIND,
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "guard": GUARD,
        "inputs": {
            "crosswalk_version": crosswalk.get("version"),
            "crosswalk_sha256": (
                "sha256:" + _sha256_hex(crosswalk_bytes)
                if crosswalk_bytes is not None
                else "sha256:" + _sha256_hex(canonical_json(crosswalk).encode())
            ),
            "frameworks": list(FRAMEWORKS),
            "row_count": len(manifest_rows),
        },
        "rows": manifest_rows,
        "framework_counts": counts,
        "table_sha256": "sha256:" + _sha256_hex(canonical_json(manifest_rows).encode()),
    }
    manifest["manifest_content_sha256"] = "sha256:" + _sha256_hex(canonical_json(manifest).encode())
    return manifest


def render(manifest: dict) -> str:
    return json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
