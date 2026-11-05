# SPDX-License-Identifier: Apache-2.0
"""W3 demo, P1.9a beat (demonstration only): portal phase 5 push outcome.

Runs the same end-to-end path as tests/test_phase5_push.py::test_full_vertical
(registry -> signed push -> gate) and prints the deployment row the portal
records: push_status accepted, chained receipt hash present. Demonstration
beat: it exercises the shipped phase 5 machinery, it adds none.

Run with the raucle-cloud venv:

    .venv/bin/python <this-file> [out-dir]
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "raucle-cloud"
sys.path.insert(0, str(ROOT))
sys.path.insert(1, str(ROOT / "tests"))

_spec = importlib.util.spec_from_file_location(
    "w3_phase5", ROOT / "tests" / "test_phase5_push.py"
)
assert _spec is not None and _spec.loader is not None
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
SCHEMA_ACC = _mod.SCHEMA_ACC


def _beat(e: dict, out_dir: Path) -> None:
    client = e["client"]
    headers = {"Authorization": f"Bearer {e['tokens']['admin']}"}

    created = client.post(
        "/api/v1/policies",
        json={
            "name": "acc-001-only",
            "tool": "lookup_balance",
            "agent_id": "agent:svc",
            "constraints": {"allow": {"account": ["ACC-001"]}},
            "tool_schema": SCHEMA_ACC,
        },
        headers=headers,
    )
    created.raise_for_status()
    policy_id = created.json()["policy"]["id"]

    activated = client.post(
        f"/api/v1/policies/{policy_id}/activate", json={}, headers=headers
    )
    activated.raise_for_status()

    rows = client.get(
        f"/api/v1/policies/{policy_id}/deployments", headers=headers
    ).json()
    row = rows["deployments"][0]
    chained = row["push_status"] == "accepted" and row["remote_receipt_hash"].startswith(
        "sha256:"
    )
    print(json.dumps(
        {
            "beat": "P1.9a phase 5 portal push",
            "policy_id": policy_id,
            "deployment_row": row,
            "chained": chained,
        },
        indent=2,
    ))
    assert chained, "deployment row is not chained"
    (out_dir / "phase5-beat.json").write_text(json.dumps(row, indent=2))
    remote = row["remote_receipt_hash"]
    print(
        f"phase 5 beat OK: push_status=accepted, remote receipt hash "
        f"{remote[:40]}... (full row: {out_dir / 'phase5-beat.json'})"
    )


def main() -> None:
    out_dir = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    with tempfile.TemporaryDirectory() as tmp:
        e = _mod._bootstrap(Path(tmp))
        try:
            _beat(e, out_dir)
        finally:
            e["server"].should_exit = True


if __name__ == "__main__":
    main()
