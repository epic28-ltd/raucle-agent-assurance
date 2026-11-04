# SPDX-License-Identifier: Apache-2.0
"""AUD-01 operator CLI: build an offline auditor export pack (P1.7a).

Thin wrapper over ops/audit-pack/pack.py so operators can run:

    python scripts/build_audit_pack.py \
      --evidence-store services/investigation-ui/demo_data/evidence_store.jsonl \
      --trust-roots services/investigation-ui/demo_data/trust_roots.jsonl \
      --from 2026-11-01 --to 2026-12-01 \
      --out /tmp/audit-pack-out

Nothing leaves the machine: the output is a local pack directory + .zip.
The module is loaded by file path (the on-disk directory name carries a
hyphen, so it is not a package identifier).
"""

from __future__ import annotations

import importlib.util
import pathlib
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

_pack_spec = importlib.util.spec_from_file_location(
    "oaa_audit_pack", REPO_ROOT / "ops" / "audit-pack" / "pack.py"
)
assert _pack_spec is not None and _pack_spec.loader is not None
_pack = importlib.util.module_from_spec(_pack_spec)
sys.modules["oaa_audit_pack"] = _pack
_pack_spec.loader.exec_module(_pack)

main = _pack.main

if __name__ == "__main__":
    raise SystemExit(main())
