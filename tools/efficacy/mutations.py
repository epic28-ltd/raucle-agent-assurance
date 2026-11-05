# SPDX-License-Identifier: Apache-2.0
"""OV-10: controls-efficacy mutation catalog v0 (run-record fixtures).

Standalone, like the other tools/ scripts: standard library only, no
project imports, no network, no clocks. Every mutation class applies to
the canonical good fixture and is REQUIRED to break an exactly-named
control, so the campaign outcome is known by construction ("known-broken
candidates" per the backlog item).

Classes (backlog OV-10 v0):

- ``evidence_link_removal``  — a privileged capability ref loses its
  receipt linkage, so the action is no longer evidenced.
- ``review_route_bypass``    — a held review is forged to approved with
  no approver or approval reference.
- ``boundary_widening``      — the declared tool boundary silently
  admits a tool the sanctioned boundary never contained.
- ``replay_duplicate``       — a receipt is replayed: the same hash
  appears twice in the receipt list and again as a fresh governance
  event.

Deterministic by literal construction: fixtures are built from
literals, mutators deep-copy and mutate a bounded field, and ``mutate``
is idempotent per call over an untouched base fixture.
"""

from __future__ import annotations

import copy

SCHEMA_VERSION = "agent_run_record/v1"
MUTATION_CATALOG_VERSION = "efficacy/mutations/v0"

# The closed, sanctioned tool boundary for the fixture. The boundary
# control compares against exactly this set: widening it is a mutation,
# never a silent edit of the contract.
SANCTIONED_TOOLS = ("search_web",)

_SHA256_LIKE = "sha256:" + "a1" * 32
_SHA256_LIKE_B = "sha256:" + "b2" * 32


def good_run_record() -> dict:
    """The known-good AgentRunRecord fixture. Deterministic literals."""
    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": "rec-fixture-0001",
        "agent": "demo-agent",
        "release": "demo-release-7",
        "started": "2026-11-05T10:00:00Z",
        "finished": "2026-11-05T10:05:00Z",
        "trace_ids": ["trc-0001"],
        "receipts": [
            {
                "receipt_hash": _SHA256_LIKE,
                "decision": "allow",
                "tool": "search_web",
                "synthetic": True,
            },
            {
                "receipt_hash": _SHA256_LIKE_B,
                "decision": "deny",
                "tool": "send_email",
                "synthetic": True,
            },
        ],
        "capability_refs": [
            {
                "tool": "search_web",
                "privileged": True,
                "via_receipt_hash": _SHA256_LIKE,
            },
        ],
        "governance_events": [
            {
                "kind": "receipt-attached",
                "decision": "allow",
                "receipt_hash": _SHA256_LIKE,
                "trace_id": "trc-0001",
            },
            {
                "kind": "review-blocked",
                "decision": "deny",
                "note": "review gate held the send_email action",
                "trace_id": "trc-0001",
            },
        ],
        "boundaries": {
            "tools": ["search_web"],
        },
        "usage_metrics": {"privileged_tool_spans": 1},
    }


class Mutation:
    """One mutation class: id, the control it attacks, the mutator."""

    def __init__(self, class_id: str, label: str, control: str, mutator):
        self.id = class_id
        self.label = label
        self.control = control
        self._mutator = mutator

    def apply(self, record: dict) -> dict:
        """Return a NEW known-broken record; the input is never mutated."""
        return self._mutator(copy.deepcopy(record))


# --- mutators (each closes over exactly one bounded edit) -------------


def _remove_evidence_link(record: dict) -> dict:
    for ref in record["capability_refs"]:
        if ref.get("tool") == "search_web":
            ref.pop("via_receipt_hash", None)
    return record


def _forge_review_approval(record: dict) -> dict:
    for event in record["governance_events"]:
        if event["kind"] == "review-blocked":
            event["kind"] = "review-approved"
            event["decision"] = "allow"
            # note deliberately dropped: the forged route carries neither
            # approver nor approval reference.
    return record


def _widen_tool_boundary(record: dict) -> dict:
    record["boundaries"]["tools"].append("send_email")
    return record


def _replay_receipt(record: dict) -> dict:
    duplicate = copy.deepcopy(record["receipts"][0])
    record["receipts"].append(duplicate)
    record["governance_events"].append(
        {
            "kind": "receipt-attached",
            "decision": "allow",
            "receipt_hash": duplicate["receipt_hash"],
            "trace_id": "trc-0001",
        }
    )
    return record


MUTATIONS: dict[str, Mutation] = {
    mut.id: mut
    for mut in (
        Mutation(
            "evidence_link_removal",
            "privileged action loses its receipt linkage",
            "every privileged capability ref carries via_receipt_hash "
            "resolving to a receipt in the record (linkage control)",
            _remove_evidence_link,
        ),
        Mutation(
            "review_route_bypass",
            "held review forged to approved without an approver",
            "every review-approved event names approved_by and an "
            "approval_ref (review-route control)",
            _forge_review_approval,
        ),
        Mutation(
            "boundary_widening",
            "declared boundary silently admits an unsanctioned tool",
            "boundaries.tools equals the sanctioned closed set (boundary control)",
            _widen_tool_boundary,
        ),
        Mutation(
            "replay_duplicate",
            "same receipt replayed: duplicate hash entry + fresh event",
            "receipt hashes are unique within a record and each has at "
            "most one receipt-attached event (replay control)",
            _replay_receipt,
        ),
    )
}


def catalog_ids() -> list:
    """Stable catalog order (v0: exactly the four backlog classes)."""
    return list(MUTATIONS)
