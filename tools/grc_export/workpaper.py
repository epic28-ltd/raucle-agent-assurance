# SPDX-License-Identifier: Apache-2.0
"""Auditor workpaper export (``workpapers/v1``) for the AIUC-1 crosswalk.

Emits a versioned, deterministic SOC 2-style workpaper document: one workpaper
per AIUC-1 crosswalk row, each carrying

- the control text, quoted verbatim from the AIUC-1 published framework
  heading the row was derived from (``control_text`` / ``source_heading``),
- hash-only evidence nodes (receipt hashes, the packet digest itself, and a
  sha256 digest of the cited evidence field's value - no receipt payload, no
  raw evidence values, no denial reasons; bounded disclosure preserved),
- an ``auditor_notes`` block that states honestly what the evidence covers,
  what it does not (gaps), and that every row is derivation-tagged.

Determinism contract: the same inputs produce byte-identical JSON (sorted
keys, stable order, no wall-clock data). An UNSUPPORTED control is exported
with an empty evidence list and its gap named in ``auditor_notes.gaps`` - the
gap is visible, never papered over. No certification, approval, attestation
or warranty of any kind is asserted; this is an internal fieldwork schedule,
not an auditor's report.
"""

from __future__ import annotations

import hashlib
import json

WORKPAPER_KIND = "workpapers"
WORKPAPER_SCHEMA_VERSION = 1
WORKPAPER_PROFILE = "aiuc1"

# Extra crosswalk fields (beyond what the graph exporter reads) that carry
# the verbatim citation set by the N7 build.
_REQUIRED_CITATION_FIELDS = (
    "derivation",
    "control_text",
    "source_heading",
    "source_url",
    "family_heading",
    "family_url",
)


class WorkpaperError(ValueError):
    """Named, user-legible failure; nothing is silently dropped or repaired."""


def canonical_json(obj: object) -> str:
    """Deterministic canonical form: sorted keys, no whitespace padding."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_of(obj: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def export_rows(crosswalk: dict, profile: str = WORKPAPER_PROFILE) -> list[dict]:
    """The crosswalk rows for a workpaper profile.

    ``aiuc1`` selects the AIUC-1 framework rows. A crosswalk that carries a
    selected row without its verbatim citation set is a named failure: an
    un-cited control never becomes a workpaper.
    """
    if profile == WORKPAPER_PROFILE:
        rows = [r for r in crosswalk.get("rows", []) if r.get("framework") == "AIUC-1"]
    else:
        raise WorkpaperError(f"unknown workpaper profile: {profile!r}")
    if not rows:
        raise WorkpaperError(f"crosswalk has no {profile} rows")
    out: list[dict] = []
    for row in rows:
        missing = [f for f in _REQUIRED_CITATION_FIELDS if f not in row]
        if missing:
            raise WorkpaperError(
                f"crosswalk row {row.get('control_id')!r} lacks verbatim citation fields:"
                f" {', '.join(sorted(missing))}"
            )
        if row.get("status") == "UNSUPPORTED" and not row.get("unsat_reason"):
            raise WorkpaperError(
                f"crosswalk row {row['control_id']!r} is UNSUPPORTED without an honest"
                " unsat_reason"
            )
        out.append(row)
    return sorted(out, key=lambda r: r["control_id"])


def build_workpaper(row: dict, packet: dict | None, dotted_lookup) -> dict:
    """One workpaper for one crosswalk row.

    ``dotted_lookup`` is the graph exporter's packet-field lookup so the two
    exporters resolve evidence fields identically.
    """
    status = row["status"]
    evidence: list[dict] = []
    if packet is not None:
        evidence.append({"kind": "packet", "id": "packet:sha256", "packet_sha256": sha256_of(packet)})
        field = row.get("evidence_field")
        if field:
            value = dotted_lookup(packet, str(field))
            if value is not None:
                evidence.append(
                    {
                        "kind": "evidence_field_digest",
                        "id": f"evidence:{field}",
                        "packet_field": str(field),
                        "value_sha256": sha256_of(value),
                    }
                )
        for rh in dotted_lookup(packet, "receipt_chain.receipt_hashes") or []:
            evidence.append({"kind": "receipt", "id": f"receipt:{rh}", "hash": rh})
    evidence = sorted(evidence, key=lambda e: (e["kind"], e["id"]))
    for node in evidence:
        for key, value in node.items():
            if key in ("hash", "packet_sha256", "value_sha256"):
                if not (isinstance(value, str) and value.startswith("sha256:")):
                    raise WorkpaperError(f"evidence node {node.get('id')!r} field {key!r} is not a sha256 hash")
                if len(value) != len("sha256:") + 64 or value[6:] != value[6:].lower():
                    raise WorkpaperError(f"evidence node {node.get('id')!r} field {key!r} is not canonical sha256")

    gaps: list[str] = []
    if status == "UNSUPPORTED":
        gaps.append(row["unsat_reason"])
    elif status == "PARTIAL":
        gaps.append(row.get("basis", ""))
    gaps = [g for g in gaps if g]
    if packet is None:
        gaps.append("no agent assurance packet supplied to this export: the evidence below is absent")

    wp: dict = {
        "control_id": row["control_id"],
        "framework": row["framework"],
        "title": row.get("title"),
        "control_text": row["control_text"],
        "source_heading": row["source_heading"],
        "source_url": row["source_url"],
        "family_heading": row["family_heading"],
        "family_url": row["family_url"],
        "derivation": row["derivation"],
        "status": status,
        "evidence_field": row.get("evidence_field"),
        "evidence": evidence,
        "auditor_notes": {
            "derivation_note": (
                "Row derived from the AIUC-1 published framework headings; the"
                " control text is quoted verbatim from source_heading/source_url"
                " and has not been paraphrased into new control text."
            ),
            "status_reason": row.get("unsat_reason") or row.get("basis"),
            "gaps": gaps,
        },
    }
    return wp


def build_workpapers(crosswalk: dict, packet: dict | None, dotted_lookup) -> dict:
    wp_rows = export_rows(crosswalk)
    workpapers = [build_workpaper(row, packet, dotted_lookup) for row in wp_rows]
    doc: dict = {
        "kind": WORKPAPER_KIND,
        "schema_version": WORKPAPER_SCHEMA_VERSION,
        "profile": WORKPAPER_PROFILE,
        "guard": (
            "Internal auditor fieldwork schedule over the AIUC-1 crosswalk rows."
            " Control text is quoted verbatim from the AIUC-1 published framework"
            " headings cited per row. Evidence nodes carry hashes only. Gaps are"
            " named, not papered over. This document asserts no certification,"
            " no approval, no attestation, and no warranty of any kind."
        ),
        "inputs": {
            "crosswalk_version": crosswalk.get("version"),
            "packet_sha256": sha256_of(packet) if packet else None,
            "workpaper_count": len(workpapers),
        },
        "workpapers": workpapers,
    }
    doc["workpaper_content_sha256"] = sha256_of(doc)
    return doc


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
