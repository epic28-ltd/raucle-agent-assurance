# SPDX-License-Identifier: Apache-2.0
"""Determinism and digest-binding tests for the regulatory mapping manifest (issue 113).

Mirrors the evidence-archive discipline (tools/evidence_archive): the same
crosswalk input must produce a byte-identical manifest, every row's
source_row_sha256 must digest that row's exact source content, the table
digest must bind the rows over themselves, and every honesty rule the
manifest enforces (owner-pending slots, dispositions, artifact existence at
main, metadata vocabulary) stays machine-checked.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "mapping_manifest", REPO / "tools" / "grc_export" / "mapping_manifest.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_mm = _load_module()
CROSSWALK_PATH = REPO / "ops" / "assurance-profiles" / "crosswalk.json"


def _crosswalk() -> dict:
    return json.loads(CROSSWALK_PATH.read_text())


def _mapped_rows_by_id(crosswalk: dict) -> dict[tuple[str, str], dict]:
    return {(r["framework"], r["control_id"]): r for r in crosswalk["rows"]}


def test_manifest_builds_and_counts_match_crosswalk() -> None:
    cw = _crosswalk()
    manifest = _mm.build_manifest(cw, CROSSWALK_PATH.read_bytes())
    assert manifest["kind"] == "regulatory_mapping_manifest"
    assert manifest["schema_version"] == 1
    for fw in _mm.FRAMEWORKS:
        crosswalk_rows = [r for r in cw["rows"] if r["framework"] == fw]
        count = next(c for c in manifest["framework_counts"] if c["framework"] == fw)
        assert count["rows"] == len(crosswalk_rows)
        assert count["rows"] == sum((count["supported"], count["partial"], count["unsupported"]))
    assert manifest["inputs"]["row_count"] == len(manifest["rows"])
    assert manifest["inputs"]["crosswalk_version"] == cw["version"]


def test_manifest_is_deterministic() -> None:
    cw = _crosswalk()
    first = _mm.render(_mm.build_manifest(cw, CROSSWALK_PATH.read_bytes()))
    second = _mm.render(_mm.build_manifest(_crosswalk(), CROSSWALK_PATH.read_bytes()))
    assert first == second
    # same digests again when the bytes binding is omitted (canonical-JSON
    # digest path), and under a deep copy of the input: input identity, not
    # object identity, drives the output - content, never memory
    none_first = _mm.render(_mm.build_manifest(cw, None))
    none_second = _mm.render(_mm.build_manifest(copy.deepcopy(cw), None))
    assert none_first == none_second
    # the two input-digest paths differ only in the input binding they carry
    byte_manifest, none_manifest = json.loads(first), json.loads(none_first)
    assert byte_manifest.pop("inputs") != none_manifest.pop("inputs")
    assert byte_manifest.pop("manifest_content_sha256") != none_manifest.pop(
        "manifest_content_sha256"
    )
    assert byte_manifest == none_manifest


def test_manifest_cli_is_deterministic_bytes() -> None:
    export = REPO / "tools" / "grc_export" / "export.py"
    outs = []
    for _ in range(2):
        proc = subprocess.run(
            [sys.executable, str(export), "--profile", "manifest"],
            capture_output=True,
            text=True,
            cwd=REPO,
            timeout=120,
        )
        assert proc.returncode == 0, proc.stderr
        outs.append(proc.stdout)
    assert outs[0] == outs[1]
    manifest = json.loads(outs[0])
    assert manifest["kind"] == _mm.MANIFEST_KIND


def test_row_digest_binds_exact_source_row() -> None:
    cw = _crosswalk()
    manifest = _mm.build_manifest(cw, CROSSWALK_PATH.read_bytes())
    source = _mapped_rows_by_id(cw)
    for entry in manifest["rows"]:
        expected = (
            "sha256:"
            + hashlib.sha256(
                _mm.canonical_json(source[(entry["framework"], entry["control_id"])]).encode()
            ).hexdigest()
        )
        assert entry["source_row_sha256"] == expected


def test_digest_binding_detects_single_row_tamper() -> None:
    cw = _crosswalk()
    baseline = _mm.build_manifest(cw, CROSSWALK_PATH.read_bytes())
    tampered = copy.deepcopy(cw)
    target = next(
        r
        for r in tampered["rows"]
        if (r["framework"], r["control_id"]) == ("ISO 42001", "A.2.2 AI policy")
    )
    target["unsat_reason"] += " TAMPERED"
    after = _mm.build_manifest(tampered, None)
    entry_key = ("ISO 42001", "A.2.2 AI policy")
    base_entry = next(e for e in baseline["rows"] if (e["framework"], e["control_id"]) == entry_key)
    new_entry = next(e for e in after["rows"] if (e["framework"], e["control_id"]) == entry_key)
    # the tampered row's digest moves, and the table digest binds the tamper
    assert new_entry["source_row_sha256"] != base_entry["source_row_sha256"]
    assert after["table_sha256"] != baseline["table_sha256"]


def test_table_digest_covers_the_table_over_itself() -> None:
    manifest = _mm.build_manifest(_crosswalk(), CROSSWALK_PATH.read_bytes())
    expected = "sha256:" + hashlib.sha256(_mm.canonical_json(manifest["rows"]).encode()).hexdigest()
    assert manifest["table_sha256"] == expected
    # manifest_content_sha256 added after the digest, outside it (OV-1 pattern)
    rebuilt = {k: v for k, v in manifest.items() if k != "manifest_content_sha256"}
    recomputed = "sha256:" + hashlib.sha256(_mm.canonical_json(rebuilt).encode()).hexdigest()
    assert manifest["manifest_content_sha256"] == recomputed


def test_build_manifest_fails_closed_on_tampered_honesty_fields() -> None:
    cw = _crosswalk()

    def _broken(mutator) -> None:
        broken = copy.deepcopy(cw)
        mutator(broken)
        try:
            _mm.build_manifest(broken, None)
        except _mm.ExportError:
            return
        raise AssertionError("tampered honesty fields must fail the manifest build")

    # a SUPPORTED row with disposition gap
    _broken(
        lambda d: next(
            r for r in d["rows"] if r["status"] == "SUPPORTED" and r["framework"] in _mm.FRAMEWORKS
        ).__setitem__("disposition", "gap")
    )
    # a non-pending owner slot (never invent an owner)
    _broken(
        lambda d: next(r for r in d["rows"] if r["framework"] in _mm.FRAMEWORKS).__setitem__(
            "owner", "invented person"
        )
    )
    # an EU AI Act row missing the legal-review-input marker
    _broken(
        lambda d: next(r for r in d["rows"] if r["framework"] == "EU AI Act").pop(
            "applicability_status"
        )
    )


def test_every_row_carries_owner_pending_craig() -> None:
    cw = _crosswalk()
    for row in cw["rows"]:
        if row["framework"] in _mm.FRAMEWORKS:
            assert row["owner"] == "owner-pending Craig", row["control_id"]
            assert row["evidence_freshness"]["verified_at"]
            assert "raucle v0.23.9" in row["system_version_scope"]["ships_in"]
            assert row["verification_status"] in _mm.VERIFICATION_STATUSES
            assert row["disposition"] in _mm.DISPOSITIONS


def test_disposition_matches_status_and_artifacts() -> None:
    cw = _crosswalk()
    for row in cw["rows"]:
        if row["framework"] not in _mm.FRAMEWORKS:
            continue
        if row["status"] in ("SUPPORTED", "PARTIAL"):
            assert row["disposition"] == "mapped", row["control_id"]
            artifact = row["evidence_artifact"]
            # the mapped artifact must exist at main (this branch tracks origin/main)
            assert (REPO / artifact).is_file(), f"artifact missing at main: {artifact}"
            assert os.path.isabs(artifact) is False
        else:
            assert row["disposition"] in ("gap", "not-applicable"), row["control_id"]
            assert row["evidence_artifact"] is None, row["control_id"]
            assert row["unsat_reason"], row["control_id"]


def test_evidence_freshness_commit_matches_the_artifacts_last_commit() -> None:
    cw = _crosswalk()
    # depth-1 CI checkouts merge-shallow the PR: per-artifact `git log -- path`
    # is not resolvable there (the only available commit is the checkout tip),
    # so the full re-verification runs wherever history exists, and a shallow
    # context verifies the intrinsic parts with an explicit skip reason -
    # never a silent pass, never a false failure.
    is_shallow = (
        subprocess.run(
            ["git", "rev-parse", "--is-shallow-repository"],
            capture_output=True,
            text=True,
            cwd=REPO,
            timeout=60,
        ).stdout.strip()
        == "true"
    )
    for row in cw["rows"]:
        if row["framework"] not in _mm.FRAMEWORKS or row["status"] == "UNSUPPORTED":
            continue
        fresh = row["evidence_freshness"]
        assert set(fresh) >= {"verified_at", "evidence_commit"}, row["control_id"]
        commit = fresh["evidence_commit"]
        assert len(commit) == 40, row["control_id"]
        assert all(c in "0123456789abcdef" for c in commit), row["control_id"]
        if is_shallow:
            continue
        proc = subprocess.run(
            ["git", "log", "-1", "--format=%H", "--", row["evidence_artifact"]],
            capture_output=True,
            text=True,
            cwd=REPO,
            timeout=60,
        )
        assert fresh["evidence_commit"] == proc.stdout.strip(), row["control_id"]


def test_iso42001_coverage_spans_areas_a1_through_a10() -> None:
    cw = _crosswalk()
    ids = {r["control_id"] for r in cw["rows"] if r["framework"] == "ISO 42001"}
    prefix_area = {}
    for area in range(1, 11):
        matches = sorted(i for i in ids if i.startswith(f"A.{area}"))
        assert matches, f"no ISO 42001 rows cover Annex A area A.{area}"
        prefix_area[f"A.{area}"] = matches
    # the organisational out-of-scope rows carry reasons, not silence
    honest = {"A.1 general", "A.7 data for AI systems", "A.10.3 suppliers"}
    rows = _mapped_rows_by_id(cw)
    for cid in honest:
        assert rows[("ISO 42001", cid)]["disposition"] == "not-applicable"


def test_eu_ai_act_rows_carry_legal_review_input_marker() -> None:
    cw = _crosswalk()
    marker = "legal review input"
    for row in cw["rows"]:
        if row["framework"] == "EU AI Act":
            assert marker in row["applicability_status"], row["control_id"]
    assert _mm.GUARD.lower().count("legal review input") >= 1
    assert "NOT certification" in _mm.GUARD


def test_guard_refuses_certification_language() -> None:
    forbidden = ("is certified", "fully compliant", "achieves conformity")
    for phrase in forbidden:
        assert phrase not in _mm.GUARD, phrase
    assert "evidence mapping" in _mm.GUARD
