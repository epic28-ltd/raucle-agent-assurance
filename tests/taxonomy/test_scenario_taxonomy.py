# SPDX-License-Identifier: Apache-2.0
"""OV-11 consistency tests for the scenario taxonomy.

The taxonomy is honest-coverage-first: every row must cite an evidence
primitive, every citation must resolve, and coverage statuses are restricted
to covered / partial / none. This module is the validator.
"""

from __future__ import annotations

import re

from taxonomy_loader import (
    EXPECTED_CAGE_1_DIMENSIONS,
    EXPECTED_OPENAGENTSAFETY_CATEGORIES,
    load_committed_red_labels,
    load_taxonomy,
    red_rule_refs,
)

TOOL_BEARING_KINDS = {"covered", "partial"}
RECEIPT_REF_PREFIXES = ("receipt:", "prebind:", "correlation:")


def test_source_row_counts_match_the_verified_sources() -> None:
    taxonomy = load_taxonomy()
    oas = [r for r in taxonomy["rows"] if r["taxonomy"] == "openagentsafety"]
    cage = [r for r in taxonomy["rows"] if r["taxonomy"] == "cage-1"]
    assert len(oas) == 8, "OpenAgentSafety declares 8 risk categories"
    assert len(cage) == 12, "CAGE-1 declares 12 dimensions"
    for source in taxonomy["sources"]:
        if source["id"] == "openagentsafety":
            assert source["rows"] == 8
        if source["id"] == "cage-1":
            assert source["rows"] == 12


def test_all_verified_source_categories_present_by_name() -> None:
    rows = load_taxonomy()["rows"]
    oas_names = {r["category"] for r in rows if r["taxonomy"] == "openagentsafety"}
    cage_names = {r["category"] for r in rows if r["taxonomy"] == "cage-1"}
    assert oas_names == set(EXPECTED_OPENAGENTSAFETY_CATEGORIES)
    assert cage_names == set(EXPECTED_CAGE_1_DIMENSIONS)


def test_row_ids_unique_and_well_formed() -> None:
    rows = load_taxonomy()["rows"]
    ids = [r["id"] for r in rows]
    assert len(ids) == len(set(ids))
    for row_id in ids:
        assert re.fullmatch(r"(OAS|CAGE)-D?\d{1,2}", row_id), row_id


def test_every_row_cites_at_least_one_reflexive_field() -> None:
    # 'none' coverage is the honest exception: a row with no primitive today
    # must say so with an empty refs list and a coverage_note explaining why.
    for row in load_taxonomy()["rows"]:
        if row["coverage"] == "none":
            assert row["primitive_refs"] == []
            assert row["coverage_note"]
        else:
            assert row["primitive_refs"], row["id"]
            assert row["coverage_note"], row["id"]


def test_coverage_status_enum_honest() -> None:
    taxonomy = load_taxonomy()
    assert set(taxonomy["coverage_statuses"]) == {"covered", "partial", "none"}
    for row in taxonomy["rows"]:
        assert row["coverage"] in taxonomy["coverage_statuses"], row["id"]


def test_red_rule_refs_resolve_against_committed_corpus_fixture() -> None:
    taxonomy = load_taxonomy()
    committed = load_committed_red_labels()
    refs = red_rule_refs(taxonomy)
    assert refs, "taxonomy rows should exercise the red findings surface"
    unknown = sorted(set(refs) - set(committed))
    assert not unknown, f"RED ids absent from the committed findings snapshot: {unknown}"


def test_receipt_shaped_refs_are_documented_vocabulary() -> None:
    for row in load_taxonomy()["rows"]:
        for ref in row.get("primitive_refs", []):
            if ref.startswith(RECEIPT_REF_PREFIXES):
                assert re.fullmatch(r"[a-z_]+:[a-zA-Z0-9_=.-]+", ref), ref


def test_prebind_vocabulary_matches_the_cage_1_boundary_outcomes() -> None:
    # CAGE-1 boundary outcomes: admitted, held, narrowed, escalated, refused,
    # quarantined, and rendered no-bind. OV-12 derives exactly these from
    # receipts, plus the documented unresolved extension (honest absence of
    # evidence: no receipt outcome may be promoted to a fabricated state).
    taxonomy = load_taxonomy()
    asserted = set(taxonomy["prebind_states"])
    cage_outcomes = {
        "admitted",
        "held",
        "narrowed",
        "escalated",
        "refused",
        "quarantined",
        "no_bind",
    }
    assert cage_outcomes | {"unresolved"} == asserted


def test_cage1_fail_closed_dimension_maps_only_to_prebind_states() -> None:
    taxonomy = load_taxonomy()
    failure_row = next(r for r in taxonomy["rows"] if r["id"] == "CAGE-D10")
    assert failure_row["primitive_kind"] == "prebind_state"
    assert any(ref.startswith("prebind:") for ref in failure_row["primitive_refs"])


def test_sources_carry_arxiv_ids() -> None:
    for source in load_taxonomy()["sources"]:
        assert re.fullmatch(r"\d{4}\.\d{4,5}", source["arxiv"]), source["id"]
