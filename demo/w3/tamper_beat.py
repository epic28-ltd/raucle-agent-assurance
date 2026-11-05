# SPDX-License-Identifier: Apache-2.0
"""Tamper helper for the W3 F7 hero beat: flip bytes inside the first
receipt's JWS in a copied pack so verify_pack.py must answer RED with a
named failure."""

import json
import sys
from pathlib import Path

pack = Path(sys.argv[1])
target = pack / "receipts.jsonl"
lines = target.read_text().splitlines()
env = json.loads(lines[0])
env["jws"] = env["jws"][:-4] + "AAAA"  # flip trailing JWS bytes, envelope stays well-formed
target.write_bytes((json.dumps(env) + "\n" + "\n".join(lines[1:]) + "\n").encode())
print("tamper applied: 4 trailing JWS bytes flipped on receipt 1 (copy only, original untouched)")
