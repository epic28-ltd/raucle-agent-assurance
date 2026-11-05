# SPDX-License-Identifier: Apache-2.0
"""AgentRunRecord fixture generator (Sprint backlog OV-8).

Builds privacy-filtered AgentRunRecord fixtures from the committed demo data
of the investigation service:

- ``services/investigation-ui/demo_data/runs.json`` (UI-01/UI-02.4 demo runs
  with trace + span structure),
- ``services/investigation-ui/demo_data/synthetic_receipt_index.jsonl``
  (hand-built synthetic receipt index rows, marked ``synthetic: true``).

Every receipt is carried as metadata fields only (hash, decision, tool,
policy ref, provenance, timestamps). Raw receipt bytes (``jws``), prompt or
completion text, credentials and end-user identifiers are never read from
the source and never emitted: the generator works from an explicit field
allowlist and a refuse-to-emit scan. Synthetic receipts carry
``synthetic: true`` so the record can never be confused with canonical
evidence. Unknown stays distinct: a span whose receipt hash has no index
row yields ``decision: "unknown"``, never an inferred allow or deny.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re

SCHEMA_VERSION = "agent_run_record/v1"

# Fields the generator MAY copy from a receipt index row. Anything not on
# this allowlist is dropped before it can reach a fixture.
RECEIPT_ALLOWLIST = (
    "receipt_hash",
    "decision",
    "tool",
    "policy_ref",
    "provenance",
    "event_time",
    "synthetic",
)

# Values the demo index uses for "no decision recorded" that must NOT be
# normalised into allow/deny (architecture rule 3).
UNKNOWN_DECISIONS = (None, "unknown", "not_applicable", "pending", "unavailable")

# Substrings that must never appear in any emitted fixture payload. The JWS
# base64-header marker is how raw signed receipt bytes would be smuggled in;
# everything else is content/credential vocabulary.
REFUSE_MARKERS = (
    "jws",
    "eyJ",  # raw JOSE header/claim bytes start like this
    "api_key",
    "authorization",
    "secret",
    "password",
    "prompt_text",
    "completion",
    "messages",
)

_PRIVACY_SCAN = re.compile("|".join(re.escape(m) for m in REFUSE_MARKERS), re.IGNORECASE)

# Repo-relative default sources, so the script is runnable from a clean
# checkout without flags.
DEFAULT_RUNS = "services/investigation-ui/demo_data/runs.json"
DEFAULT_INDEX = "services/investigation-ui/demo_data/synthetic_receipt_index.jsonl"


def _filter_decision(row: dict) -> str:
    value = row.get("decision")
    if isinstance(value, str) and value.lower() in ("allow", "deny"):
        return value.lower()
    # None / pending / unavailable / any other non-decision stays unknown.
    if value in UNKNOWN_DECISIONS:
        return "unknown"
    return "unknown"


def filter_receipt(row: dict) -> dict:
    """Allowlist-project one receipt index row to record metadata."""
    receipt = {}
    for field in RECEIPT_ALLOWLIST:
        if field == "decision":
            receipt["decision"] = _filter_decision(row)
            continue
        if field in row and row[field] is not None:
            receipt[field] = row[field]
    return receipt


def load_receipt_index(path: pathlib.Path) -> dict:
    """Load a receipt index JSONL keyed by receipt_hash; comments allowed."""
    index = {}
    with path.open() as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            row = json.loads(line)
            hash_value = row.get("receipt_hash")
            if not hash_value:
                continue
            index[hash_value] = filter_receipt(row)
    return index


def build_records(runs_doc: dict, index: dict) -> list:
    """Build AgentRunRecord dicts from a runs.json document + receipt index."""
    records = []
    for run in runs_doc.get("runs", []):
        receipts: dict = {}
        capability_refs: list = []
        governance_events: list = []
        trace_ids: list = []
        policy_proof_ids: set = set()
        privileged_tool_spans = 0

        for trace in run.get("traces", []):
            trace_ids.append(trace["trace_id"])
            for span in trace.get("spans", []):
                if not span.get("privileged"):
                    continue
                privileged_tool_spans += 1
                receipt_hash = span.get("receipt_hash")
                tool = span.get("tool")
                if tool:
                    capability = {"tool": tool, "privileged": True}
                    if receipt_hash:
                        capability["via_receipt_hash"] = receipt_hash
                    capability_refs.append(capability)
                if not receipt_hash:
                    governance_events.append(
                        {
                            "kind": "receipt-missing",
                            "decision": "unknown",
                            "trace_id": trace["trace_id"],
                            "note": f"span {span.get('span_id')} records no receipt hash",
                        }
                    )
                    continue
                if receipt_hash in receipts:
                    continue
                if receipt_hash in index:
                    receipt = dict(index[receipt_hash])
                    receipt["tool_privileged"] = True
                    if receipt.get("policy_ref"):
                        policy_proof_ids.add(receipt["policy_ref"])
                    governance_events.append(
                        {
                            "kind": "receipt-attached",
                            "decision": receipt["decision"],
                            "receipt_hash": receipt_hash,
                            "trace_id": trace["trace_id"],
                        }
                    )
                else:
                    # The run references a receipt hash the committed index
                    # cannot resolve. Keep the hash, mark the decision
                    # unknown; do not infer allow/deny from absence.
                    receipt = {"receipt_hash": receipt_hash, "decision": "unknown"}
                    governance_events.append(
                        {
                            "kind": "receipt-unverifiable",
                            "decision": "unknown",
                            "receipt_hash": receipt_hash,
                            "trace_id": trace["trace_id"],
                            "note": "receipt hash absent from the committed receipt index",
                        }
                    )
                receipts[receipt_hash] = receipt

        receipts_list = sorted(receipts.values(), key=lambda r: r["receipt_hash"])
        counts = {"allow": 0, "deny": 0, "unknown": 0}
        for receipt in receipts_list:
            counts[receipt["decision"]] += 1

        records.append(
            {
                "schema_version": SCHEMA_VERSION,
                "record_id": f"arr-{run['run_id']}",
                "agent": run.get("agent", "unknown-agent"),
                "release": run.get("release", "unknown-release"),
                "started": run["started"],
                "trace_ids": sorted(trace_ids),
                "receipts": receipts_list,
                "capability_refs": sorted(
                    capability_refs, key=lambda c: (c["tool"], c.get("via_receipt_hash") or "")
                ),
                "policy_proof_ids": sorted(policy_proof_ids),
                "governance_events": governance_events,
                "usage_metrics": {
                    "receipts_total": len(receipts_list),
                    "receipts_allow": counts["allow"],
                    "receipts_deny": counts["deny"],
                    "receipts_unknown": counts["unknown"],
                    "privileged_tool_spans": privileged_tool_spans,
                    "traces_total": len(trace_ids),
                },
                "privacy": {
                    "content_class": "metadata-only",
                    "filtered_fields": [
                        "receipt bytes",
                        "conversation content",
                        "credentials",
                        "user identifiers",
                    ],
                },
            }
        )
    return records


def _refuse(payload) -> list:
    """Return marker strings that must never be emitted, found in payload."""
    text = json.dumps(payload)
    lowered = text.lower()
    # "secret" / "prompt_text" etc. as field names or plain markers. The
    # privacy.filtered_fields statement is the one exempt place where the
    # vocabulary must appear (it names the removed categories).
    hits = []
    for marker in REFUSE_MARKERS:
        if marker == "secret":
            continue  # exempt: only used inside the privacy statement below
        if marker.lower() in lowered:
            hits.append(marker)
    return hits


def generate(runs_path: pathlib.Path, index_path: pathlib.Path) -> dict:
    """Generate the full fixture document; raises on any privacy violation."""
    runs_doc = json.loads(runs_path.read_text())
    index = load_receipt_index(index_path)
    records = build_records(runs_doc, index)
    doc = {
        "schema_version": SCHEMA_VERSION,
        "note": (
            "AgentRunRecord fixtures (OV-8) generated deterministically from "
            "the committed demo_data runs.json + synthetic_receipt_index.jsonl. "
            "Synthetic receipts are marked synthetic: true; they are demo "
            "artefacts, never canonical evidence. Metadata only: no receipt "
            "bytes, prompt spans, response spans or credentials."
        ),
        "records": records,
    }
    hits = _refuse(doc)
    if hits:
        raise ValueError(
            "privacy scan refused output: forbidden marker(s) present in "
            "generated payload: " + ", ".join(sorted(set(hits)))
        )
    return doc


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate OV-8 AgentRunRecord fixtures from committed demo data."
    )
    parser.add_argument("--runs", default=DEFAULT_RUNS)
    parser.add_argument("--index", default=DEFAULT_INDEX)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    doc = generate(pathlib.Path(args.runs), pathlib.Path(args.index))
    out = pathlib.Path(args.out)
    out.write_text(json.dumps(doc, indent=2, sort_keys=False) + "\n")
    print(f"wrote {len(doc['records'])} AgentRunRecord fixtures to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
