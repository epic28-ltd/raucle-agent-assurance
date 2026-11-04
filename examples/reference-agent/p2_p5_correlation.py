#!/usr/bin/env python3
"""OBS-01 P2 + raucle correlation: score attachment with version metadata; gateway receipts keyed by
the OTel trace id; verify with ProvenanceVerifier; attach receipt hashes to the Langfuse trace via
the scores API (trace-side only); sha256 receipt file before/after to prove immutability."""

import base64
import hashlib
import json
import pathlib
import sys

OBS = pathlib.Path.home() / "Projects/oaa-spike-4nov/obs01"
CREDS = {}
for line in (OBS / "obs.env").read_text().splitlines():
    k, _, v = line.partition("=")
    CREDS[k] = v
import requests

S = requests.Session()
S.auth = (CREDS["LANGFUSE_INIT_PROJECT_PUBLIC_KEY"], CREDS["LANGFUSE_INIT_PROJECT_SECRET_KEY"])
LF = "http://localhost:3301"
orig = json.loads((OBS / "originals.json").read_text())
TRACE_ID = orig["otel_trace_id"]  # Langfuse adopts the OTel trace id as its trace id in dual mode

# ---------- P2: score with version metadata ----------
score_body = {
    "id": "obs01-score-eval-0001",
    "traceId": TRACE_ID,
    "name": "oaa.eval.result",
    "value": 0.87,
    "dataType": "NUMERIC",
    "comment": "evaluator=stub-eval;eval_version=v0.3.1;rubric=r-2026-11-04",
    "environment": "oaa-spike",
}
r = S.post(f"{LF}/api/public/scores", json=score_body, timeout=20)
p2_post = {"status": r.status_code, "body": r.json()}
rb = S.get(f"{LF}/api/public/scores", params={"traceId": TRACE_ID}, timeout=20)
p2_read = rb.json()
match = [s for s in p2_read.get("data", []) if s.get("id") == score_body["id"]]
if not match:  # fallback: read by id directly
    one = S.get(f"{LF}/api/public/scores/{score_body['id']}", timeout=20)
    if one.status_code == 200:
        match = [one.json()]
p2 = {
    "score_post": p2_post,
    "readback": match[0] if match else p2_read,
    "roundtrip_ok": bool(match)
    and float(match[0]["value"]) == 0.87
    and match[0].get("comment") == score_body["comment"],
}
print("P2 post:", p2_post["status"], "| roundtrip:", p2["roundtrip_ok"])
(OBS / "p2_report.json").write_text(json.dumps(p2, indent=2))

# ---------- raucle gateway: one allow + one deny, keyed by Langfuse trace id ----------
sys.path.insert(0, str(pathlib.Path.home() / "Projects" / "raucle"))
from raucle.gateway import GatewayConfig, RaucleGateway
from raucle.provenance import ProvenanceVerifier

RECEIPTS = OBS / "receipts.jsonl"
if RECEIPTS.exists():
    RECEIPTS.unlink()
POLICY = """
version: 1
issuer: obs01.spike
policies:
  - tool: read_file
    agent_id: agent:oaa-spike
    ttl_seconds: 300
    constraints:
      allow:
        path: ["/tmp/report.txt"]
  - tool: write_file
    agent_id: agent:oaa-spike
    ttl_seconds: 300
    constraints:
      allow:
        path: ["/sandbox/only.txt"]
"""
(OBS / "policies.yaml").write_text(POLICY)
cfg = GatewayConfig(
    host="127.0.0.1",
    admin_api_key="obs01",
    signer_backend="local",
    policy_file=str(OBS / "policies.yaml"),
    receipt_store=str(RECEIPTS),
    audit_chain=str(OBS / "audit.jsonl"),
    registry_path=str(OBS / "registry.jsonl"),
    emit_receipts=True,
)
gw = RaucleGateway(cfg)
r_allow = gw.check_tool_call(
    "read_file",
    {"path": "/tmp/report.txt"},
    agent_id="agent:oaa-spike",
    source="agent",
    destination="fs",
    trace_id=TRACE_ID,
)
r_deny = gw.check_tool_call(
    "write_file",
    {"path": "/etc/passwd"},
    agent_id="agent:oaa-spike",
    source="agent",
    destination="fs",
    trace_id=TRACE_ID,
)
print(
    "gateway allow:",
    r_allow["decision"],
    r_allow["receipt_id"][:16],
    "| deny:",
    r_deny["decision"],
    r_deny["receipt_id"][:16],
)

sha_before = hashlib.sha256(RECEIPTS.read_bytes()).hexdigest()

ver = ProvenanceVerifier(public_keys={gw.gate_identity.key_id: gw.gate_identity.public_key_pem()})
report = ver.verify_chain(str(RECEIPTS))
print("ProvenanceVerifier before attach: valid =", report.valid)

want_ids = {r_allow["receipt_id"], r_deny["receipt_id"]}
# Pull full envelope lines from the store; receipt_hash lives there verbatim.
want = {}
for line in RECEIPTS.read_bytes().splitlines():
    rec = json.loads(line)
    if (
        rec["receipt_hash"] in {f"sha256:{i}" for i in want_ids}
        or rec["receipt_hash"].split("sha256:")[-1] in want_ids
        or rec["receipt_hash"] in want_ids
    ):
        want[rec["receipt_hash"]] = line.decode()
assert len(want) == 2, want.keys()
# Attach trace-side: one score per receipt hash carrying receipt_hash + gate decision.
# Receipt bytes are never touched; only backend-agnostic references cross into the backend.
for rh, line in sorted(want.items()):
    rec = json.loads(line)
    payload = json.loads(base64.urlsafe_b64decode(rec["jws"].split(".")[1] + "=="))
    dec = payload["guardrail_verdict"]
    b = {
        "traceId": TRACE_ID,
        "name": "oaa.gate.receipt",
        "value": 1.0 if dec == "allow" else 0.0,
        "dataType": "NUMERIC",
        "comment": f"gate_decision={dec};receipt_hash={rh};verifier={'valid' if report.valid else 'invalid'}",
        "environment": "oaa-spike",
    }
    rr = S.post(f"{LF}/api/public/scores", json=b, timeout=20)
    print("receipt-correlation score", dec, "->", rr.status_code)

sha_after = hashlib.sha256(RECEIPTS.read_bytes()).hexdigest()
immutable = sha_before == sha_after
print("receipt file sha256 unchanged:", immutable, "|", sha_before[:16])
post2 = ver.verify_chain(str(RECEIPTS))
print("ProvenanceVerifier after attach: valid =", post2.valid)

(BASE := OBS / "p5_receipts_report.json").write_text(
    json.dumps(
        {
            "otel_trace_id": TRACE_ID,
            "allow_receipt_id": r_allow["receipt_id"],
            "deny_receipt_id": r_deny["receipt_id"],
            "allow_receipt_hash": r_allow["receipt_id"],
            "deny_receipt_hash": r_deny["receipt_id"],  # receipt_id IS the hash
            "verify_before": report.valid,
            "verify_after": post2.valid,
            "sha256_before": sha_before,
            "sha256_after": sha_after,
            "immutable": immutable,
            "receipt_count": len(RECEIPTS.read_text().strip().splitlines()),
        },
        indent=2,
    )
)
print("P5 immutability:", immutable, "| verifier before/after:", report.valid, post2.valid)
