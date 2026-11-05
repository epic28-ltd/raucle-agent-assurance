# SPDX-License-Identifier: Apache-2.0
"""Green-board summary for the W3 F2 beat: read the newest regression run
record and print the board line an operator would read."""

import json
import sys

path = sys.argv[1]
with open(path) as fh:
    rec = [json.loads(line) for line in fh][-1]
c = rec["check_counts"]
print(
    f"board: run={rec['run_id']} trigger={rec['trigger']} "
    f"pass={c['pass']} violation={c['violation']} drift={c['drift']} "
    f"unverified={c['unverified']} unexpected={c['unexpected']}"
)
res = rec["regression"]
print(
    f"board: regression reopened={len(res['reopened'])} resolved={len(res['resolved'])} "
    f"new={len(res['new'])} gone={len(res['gone'])}"
)
if rec["violation_receipts"]:
    print("board: violation receipts:", json.dumps(rec["violation_receipts"])[:200])
else:
    print("board: no violations to receipt; green board on violations and drift")
