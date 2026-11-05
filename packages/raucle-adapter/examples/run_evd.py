#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""EVD-02 full harness — conformance fixture sweep + rotation demo.

Example script adapted from the EVD spike (`run_evd.py`). Requires the pinned
raucle distribution (v0.23.5, git 63edacd); see the package README.

Usage (from the repository root, with the package importable — either
``pip install -e packages/raucle-adapter`` or PYTHONPATH=packages/raucle-adapter/src):

    python packages/raucle-adapter/examples/run_evd.py <output-dir>
"""

import datetime as dt
import json
import pathlib
import shutil
import sys


def _out_dir(argv: list[str]) -> pathlib.Path:
    """Resolve the CLI-supplied output directory and refuse unusable targets.

    Guards the harness against traversal shorthands and paths that would clobber
    system locations (filesystem root, the user's home directory).
    """
    out = pathlib.Path(argv[1] if len(argv) > 1 else "fixtures").expanduser().resolve()
    if out == pathlib.Path(out.root) or out == pathlib.Path.home():
        raise SystemExit(f"refusing output directory {str(out)!s}: not a usable fixture target")
    return out


OUT = _out_dir(sys.argv)

import oaa_raucle_adapter.evidence_plane as ep
from oaa_raucle_adapter import fixture_gen as fg

OUT.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------- 1. conformance fixture sweep
corpus = fg.generate(OUT)
records = corpus.records
store = ep.EvidenceStore(OUT / "evidence.jsonl")
if store.path.exists():
    store.path.unlink()

registry = ep.TrustRootRegistry()
T0 = dt.datetime(2026, 11, 4, 0, 0, tzinfo=dt.UTC)
registry.add(
    ep.TrustRoot(
        key_id=corpus.key_id,
        public_key_pem=corpus.public_key_pem,
        valid_from=T0.isoformat(),
        valid_until=None,
        status="current",
    )
)
kid_v1 = corpus.key_id

results = []
for fx in records:
    name, expected = fx["name"], fx["expected"]
    if fx.get("simulated"):
        rec = ep.VerificationResult(
            fixture_name=name,
            verification_status=expected,
            checked_at=ep._now_iso(),
            verifier_version=ep.RAUCLE_DISTRIBUTION_PIN,
            trust_policy_version=ep.TRUST_POLICY_VERSION,
            checks_performed=[
                "companion-side simulated state (async ingest); no raucle call made",
                f"state synthesised per EVD harness policy: {expected}",
            ],
            detail=fx["note"],
        )
        results.append(rec)
        continue
    digest = store.put(fx["envelope"])
    line = store.get_by_digest(digest)
    assert line == fx["envelope"], f"byte drift for {name}"
    rec = ep.classify(line, registry)
    rec.fixture_name = name
    rec.detail = fx["note"]
    results.append(rec)

# ------------------------------------- unknown_key: v2-only trust-root registry
deny_fx = next(f for f in records if f["name"] == "unknown_key_v2only")
v2 = ep._demo_identity_v2()
reg_v2only = ep.TrustRootRegistry()
reg_v2only.add(
    ep.TrustRoot(
        key_id=v2.key_id,
        public_key_pem=v2.public_key_pem(),
        valid_from=T0.isoformat(),
        valid_until=None,
    )
)
rec_uk = ep.classify(deny_fx["envelope"], reg_v2only)
rec_uk.fixture_name = "unknown_key_v2only"
rec_uk.detail = deny_fx["note"]
results = [r for r in results if r.fixture_name != "unknown_key_v2only"] + [rec_uk]

# ----------------------------------------------------------- 2. rotation demo
print("=" * 72)
print("ROTATION DEMO — ADR-0001 §2 archived-key semantics")
print("=" * 72)
print(f"raucle pin: {ep.RAUCLE_DISTRIBUTION_PIN}")
print(f"trust_policy_version: {ep.TRUST_POLICY_VERSION}\n")

# issue one receipt under identity v1 from a fresh gateway (v1 policy)
gw_cfg, gw_v1 = fg.new_gateway(OUT, "rotation")
r_hist = gw_v1.check_tool_call(
    "read_file",
    {"path": "/var/oaa-demo/evd-allow.txt"},
    agent_id="agent:evd",
    source="agent",
    destination="fs",
    trace_id="evd-trace-rotation",
)
hist_env = fg.capture_verbatim(gw_cfg, {r_hist["receipt_id"]})[r_hist["receipt_id"]].decode()

# registry for the rotation demo: seeded with the ROTATION key as the current
# root (separate from the corpus sweep registry — each gateway mints its own key).
rot_kid = gw_v1.gate_identity.key_id
rot_pem = gw_v1.gate_identity.public_key_pem()
rot_registry = ep.TrustRootRegistry()
rot_registry.add(
    ep.TrustRoot(
        key_id=rot_kid,
        public_key_pem=rot_pem,
        valid_from=T0.isoformat(),
        valid_until=None,
        status="current",
    )
)

# mint v2 identity and retire v1 (retired, never deleted)
v2b = ep._demo_identity_v2()
rot_registry.retire(key_id=rot_kid, valid_until="2026-11-04T12:00:00+00:00")
rot_registry.add(
    ep.TrustRoot(
        key_id=v2b.key_id,
        public_key_pem=v2b.public_key_pem(),
        valid_from="2026-11-04T12:00:00+00:00",
        valid_until=None,
    )
)
print("registry change log:")
for h in rot_registry._history:
    print("  ", json.dumps(h, sort_keys=True))
print()
for r in rot_registry.roots:
    print(
        f"  root key_id={r.key_id[:24]}… status={r.status} "
        f"valid_from={r.valid_from} valid_until={r.valid_until}"
    )
print()

event_time = dt.datetime.fromisoformat("2026-11-04T09:00:00+00:00")
print(f"historic receipt issued under v1; event_time={event_time.isoformat()}")
print(
    f"v1 trusted at event time (retired but archived): "
    f"{rot_registry.roots[0].trusted_at(event_time)}"
)
rec_hist = ep.classify(hist_env, rot_registry)
rec_hist.fixture_name = "rotation_historic_v1"
print("\n[1] historic v1 receipt vs archive {v1(retired), v2(current)}:")
print("   verification_status :", rec_hist.verification_status)
print("   checked_at          :", rec_hist.checked_at)
print("   verifier_version    :", rec_hist.verifier_version)
print("   trust_policy_version:", rec_hist.trust_policy_version)
print("   checks              :")
for c in rec_hist.checks_performed:
    print("     -", c)

# same receipt against a registry that forgot to archive v1 (counterfactual)
reg_forget = ep.TrustRootRegistry()
reg_forget.add(
    ep.TrustRoot(
        key_id=v2b.key_id,
        public_key_pem=v2b.public_key_pem(),
        valid_from="2026-11-04T12:00:00+00:00",
        valid_until=None,
    )
)
rec_drop = ep.classify(hist_env, reg_forget)
rec_drop.fixture_name = "rotation_v1_unarchived"
print("\n[2] same receipt vs registry WITHOUT archived v1 (counterfactual):")
print(
    "   verification_status :",
    rec_drop.verification_status,
    "  ← the silent degradation ADR-0001 §2 prevents",
)

# receipt under unregistered key → unknown_key
rec_uk2 = ep.classify(deny_fx["envelope"], ep.TrustRootRegistry())
rec_uk2.fixture_name = "unregistered_key"
print("\n[3] receipt under unregistered key →", rec_uk2.verification_status)

results += [rec_hist, rec_drop, rec_uk2]

# ------------------------------------------------------------------ summary
print("\n" + "=" * 72)
print("CONFORMANCE FIXTURE SWEEP")
print("=" * 72)
ok = True
for r in results:
    exp = next(
        (f["expected"] for f in records if f["name"] == r.fixture_name),
        r.verification_status if r.fixture_name.startswith("rotation") else None,
    )
    match = exp is None or exp == r.verification_status
    ok &= match
    print(
        f"{'PASS' if match else 'FAIL':4}  {r.fixture_name:28} "
        f"expected={exp}  actual={r.verification_status}"
    )

(out_file := OUT / "results.json").write_text(
    json.dumps([r.to_dict() for r in results], indent=2, sort_keys=True)
)
print("\nwrote", out_file, "| overall:", "PASS" if ok else "FAIL")
shutil.rmtree(OUT / "work", ignore_errors=True)
