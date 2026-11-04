#!/usr/bin/env python3
"""OBS-03 smoke: run compliance-ticket-triage twice (normal + designed deny).

Proves the LangGraph adapter contract (RaucleGateMiddleware + GateClient +
SpanAttributeSink/AuditSink callbacks) reuses for a SECOND workflow with a
different shape, without any core rewrite. Prints, per run:

- the span tree summary (AGENT -> RETRIEVER x2 -> LLM -> gated TOOL),
- the ``oaa.*`` attribute readback (run-two prefix ``oaa-run2-*``),
- the gate decision / receipt state on the gated tool span, and
- the tool-side file-write ledger (absence of the denied row = the veto held).

If the local spike Langfuse (127.0.0.1 only) is reachable AND obs.env or the
LANGFUSE_INIT_* env vars are present, real traces are pushed and verified via
the readback API; otherwise the push is SKIPPED and the local recorder output
is the evidence. Nothing external at runtime except that optional push.
"""

import socket
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE.parent.parent / "integrations" / "langgraph-adapter" / "src"))

import workflow_two as w2


def langfuse_push_possible() -> bool:
    """Push only to loopback Langfuse with creds present; skippable otherwise."""
    creds = w2._load_langfuse_creds()
    if not creds:
        return False
    try:
        # TCP reachability probe only: the gate endpoint is loopback by
        # construction, no fetch of dynamic URLs (semgrep-clean).
        with socket.create_connection(("127.0.0.1", 3301), timeout=2):
            return True
    except OSError:
        return False


def report(title: str, result: dict) -> None:
    recorder = result["recorder"]
    print(f"\n=== {title} (run_id={result['run_id']}, label={result['trace_label']}) ===")
    print("-- span tree --")
    print(recorder.tree_text())
    print("-- oaa.* readback --")
    for span_name, attrs in recorder.oaa_readback().items():
        print(f"{span_name}:")
        for k, v in attrs.items():
            print(f"    {k}: {v}")
    print("-- gate / ledger --")
    print(f"gate_decision:   {result['gate_decision']}")
    print(f"receipt_hash:    {result['receipt_hash']}")
    print(f"tool_result:     {str(result['tool_result'])[:110]}")
    print(f"ledger rows:     {result['ledger_rows']}")


def main() -> None:
    push = langfuse_push_possible()
    print(
        f"Langfuse push: {'ENABLED (loopback 127.0.0.1:3301)' if push else 'SKIPPED (local-only)'}"
    )

    normal = w2.run_workflow(deny=False, push=push)
    deny = w2.run_workflow_deny(push=push)
    report("NORMAL: in-scope gated file_write", normal)
    report("DESIGNED FAILURE: out-of-scope write -> deny", deny)

    checks = [
        ("normal: gate allowed", normal["gate_decision"] == "allow"),
        ("normal: signed receipt on span", str(normal["receipt_hash"]).startswith("sha256:")),
        ("normal: tool body ran (ledger row present)", normal["ledger_has_write_row"]),
        ("deny: gate denied", deny["gate_decision"] == "deny"),
        ("deny: NO receipt (no verification state)", deny["receipt_hash"] is None),
        ("deny: tool body never ran (ledger row ABSENT)", not deny["ledger_has_write_row"]),
        (
            "run-two prefix on both run ids",
            normal["run_id"].startswith(w2.RUN_ID_PREFIX)
            and deny["run_id"].startswith(w2.RUN_ID_PREFIX),
        ),
    ]
    print("\n=== checks ===")
    ok = True
    for name, passed in checks:
        print(f"{'PASS' if passed else 'FAIL'} {name}")
        ok = ok and passed
    print("SMOKE:", "ALL PASS" if ok else "FAILURES PRESENT")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
