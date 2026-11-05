# SPDX-License-Identifier: Apache-2.0
"""P1.7V role-play CLI: run the second-laptop verification story locally.

    python scripts/second_laptop_roleplay.py --work-dir /tmp/p1-7v

Builds a fresh real audit pack, hands the pack plus verify_pack.py to a
throwaway "second laptop" directory, verifies it inside a denied network
namespace, proves the deliberate-tamper RED path offline, re-renders and
signs the claim sheet, and leaves honest role-play notes in the directory.
Exit 0 only if every step passed its expectation.
"""

from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

_spec = importlib.util.spec_from_file_location(
    "oaa_second_laptop", REPO_ROOT / "ops" / "audit-pack" / "second_laptop.py"
)
assert _spec is not None and _spec.loader is not None
role_play = importlib.util.module_from_spec(_spec)
sys.modules["oaa_second_laptop"] = role_play
_spec.loader.exec_module(role_play)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Run the P1.7V second-laptop auditor role-play")
    ap.add_argument("--work-dir", required=True, help="throwaway directory for the role-play")
    ap.add_argument("--clock", help="pinned clock, ISO-8601 (deterministic render)")
    args = ap.parse_args(argv)

    clock = None
    if args.clock:
        clock = dt.datetime.fromisoformat(args.clock)
        if clock.tzinfo is None:
            clock = clock.replace(tzinfo=dt.UTC)

    result = role_play.run_second_laptop_role_play(pathlib.Path(args.work_dir), clock=clock)
    print("Role-play complete. Verdicts observed:")
    for line in result["verification_green"].splitlines():
        if line.startswith("OVERALL VERDICT:"):
            print(line)
    for line in result["verification_tamper"].splitlines():
        if line.startswith("OVERALL VERDICT:"):
            print(line)
    if result["network_probe"] is None:
        print("NOTE: no network namespace was proven; see " + result["isolation_note"])
    else:
        print("Network denial proven: " + result["isolation_note"])
    print("Signed claim sheet: " + result["claim_sheet_signed"])
    print("Notes: " + str(pathlib.Path(result["laptop_dir"]) / "role-play-notes.md"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
