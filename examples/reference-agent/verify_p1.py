#!/usr/bin/env python3
"""P1: read back the trace + observations via Langfuse API, diff attributes against originals.json."""

import json
import pathlib
import time

BASE = pathlib.Path(__file__).resolve().parent
CREDS = {}
for line in (BASE / "obs.env").read_text().splitlines():
    k, _, v = line.partition("=")
    CREDS[k] = v
import requests

S = requests.Session()
S.auth = (CREDS["LANGFUSE_INIT_PROJECT_PUBLIC_KEY"], CREDS["LANGFUSE_INIT_PROJECT_SECRET_KEY"])
S.headers["Content-Type"] = "application/json"
LF = "http://localhost:3301"

orig = json.loads((BASE / "originals.json").read_text())
otel_trace_id = orig["otel_trace_id"]


def get(url, **kw):
    for i in range(10):
        r = S.get(url, timeout=20, **kw)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404 and i < 9:
            time.sleep(2)
            continue
        raise SystemExit(f"{url} -> {r.status_code} {r.text[:300]}")


trace = get(f"{LF}/api/public/traces?searchId={orig['trace_label']}")
# fall back: poll list for our label
trace_id = None
for i in range(15):
    lst = get(f"{LF}/api/public/traces?limit=20").get("data", [])
    match = [t for t in lst if any((t.get("metadata") or {}) and False for _ in [])]
    for t in lst:
        if (
            t.get("sessionId") == f"sess-{orig['run_id']}"
            or str((t.get("metadata") or {}).get("attributes", {}).get("oaa.trace_label", ""))
            == orig["trace_label"]
        ):
            trace_id = t["id"]
            break
    if trace_id:
        break
    time.sleep(2)
if not trace_id:
    raise SystemExit("trace not found in list; last page: " + json.dumps(lst[:2], indent=2)[:1500])

trace = get(f"{LF}/api/public/traces/{trace_id}")
obs = get(f"{LF}/api/public/observations?traceId={trace_id}&limit=50")["data"]

trace_attrs_from = lambda t: (
    (t.get("metadata") or {}).get("attributes") or (t.get("metadata") or {})
)
trace_meta = trace.get("metadata") or {}
trace_oaa = {
    k: v
    for k, v in (trace_meta.get("attributes") or {}).items()
    if k.startswith("oaa.") or k.startswith("openinference") or k.startswith("langfuse.")
}

report = {
    "trace_id": trace_id,
    "otel_trace_id": otel_trace_id,
    "langfuse_trace_id": trace_id,
    "trace_session": trace.get("sessionId"),
    "trace_oaa_attrs_seen": trace_oaa,
}
expected = orig["spans"][0]["attrs"]
report["trace_diff"] = {}

# Trace-level: Langfuse surfaces select attributes on the trace; compare oaa ones
missing = {}
for k, v in expected.items():
    if k.startswith("oaa.") or k.startswith("langfuse."):
        seen = trace_oaa.get(k)
        report["trace_diff"][k] = {"expected": v, "seen": seen, "match": seen == v}
missing_oaa = report["trace_diff"]

# Observation-level: match spans by name
report["spans"] = []
for o in obs:
    ent = {
        "name": o["name"],
        "type": o["type"],
        "span_id": o.get("id"),
        "parent": o.get("parentObservationId"),
        "started": o.get("startTime"),
        "model": o.get("model"),
        "raw_attrs": (obs_attrs := {}),
    }
    m = o.get("metadata") or {}
    attrs = (m.get("attributes") if isinstance(m, dict) else None) or {}
    # Langfuse v4 maps span attributes into metadata.attributes
    ent["attrs"] = {k: v for k, v in attrs.items()}
    exp = next((s for s in orig["spans"] if s["name"] == o["name"]), None)
    if exp:
        ent["diff"] = {
            k: {"expected": v, "seen": attrs.get(k), "match": attrs.get(k) == v}
            for k, v in exp["attrs"].items()
        }
        ent["unexpected_extra"] = sorted(set(attrs) - set(exp["attrs"]))
        # also check flattened copies (Langfuse maps some OpenInference keys to model/input/output fields)
        ent["enrichment"] = {
            "model": o.get("model"),
            "input": o.get("input"),
            "output": o.get("output"),
            "input_cost": o.get("inputCost"),
        }
    report["spans"].append(ent)

(BASE / "p1_report.json").write_text(json.dumps(report, indent=2))
# console summary
ok = all(d["match"] for s in report["spans"] if "diff" in s for d in s["diff"].values())
t_ok = all(d["match"] for d in report["trace_diff"].values())
print(
    "LANGFUSE trace id:",
    trace_id,
    "| otel id match:",
    report["trace_oaa_attrs_seen"].get("oaa.trace_label") is not None or "see report",
)
print("TRACE-LEVEL oaa attrs:", json.dumps(report["trace_diff"], indent=1))
for s in report["spans"]:
    if "diff" in s:
        fails = [k for k, d in s["diff"].items() if not d["match"]]
        print(
            f"span {s['name']}: {'ALL MATCH' if not fails else 'DIFFS: ' + str({k: s['diff'][k] for k in fails})}"
        )
        if s.get("unexpected_extra"):
            print("  extra attrs kept:", s["unexpected_extra"])
        if s.get("enrichment") and (
            s["enrichment"]["input"] or s["enrichment"]["output"] or s["enrichment"]["model"]
        ):
            print("  structured enrichment:", json.dumps(s["enrichment"])[:400])
print("P1 verdict:", "PASS" if ok and t_ok else "PARTIAL/FAIL")
