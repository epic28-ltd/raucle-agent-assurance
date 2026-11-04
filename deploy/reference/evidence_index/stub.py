#!/usr/bin/env python3
"""OPS-01 evidence-index stub: volume-backed append-only receipt store.

Deliberately minimal (stdlib http.server, no framework): validates the mounted
store volume, the receipt read path across backup/restore round-trips, and the
healthcheck contract. The planned real evidence-index service replaces this
(see services/evidence-index/README.md); its store format (receipts.jsonl, one
JSON object per line) will be migrated as-is.

API (port ${OAA_EVIDENCE_PORT:-3302} on 127.0.0.1):
  GET  /healthz            -> {"status":"ok","receipts":N}
  POST /receipts           -> 201 {"stored": id}   (body: {"id": "...", ...})
  GET  /receipts/<id>      -> receipt JSON or 404
  GET  /receipts           -> {"receipts": [...]}
Store: $OAA_STORE_DIR/receipts.jsonl (fsync'd append; duplicate id -> no-op).
"""

import json
import os
import pathlib
from http.server import BaseHTTPRequestHandler, HTTPServer

STORE = pathlib.Path(os.environ.get("OAA_STORE_DIR", "/store"))
RECEIPTS = STORE / "receipts.jsonl"


def _load():
    if not RECEIPTS.exists():
        return []
    out = []
    for line in RECEIPTS.read_text().splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def _append(rec: dict) -> bool:
    STORE.mkdir(parents=True, exist_ok=True)
    rid = rec.get("id")
    if rid and any(r.get("id") == rid for r in _load()):
        return False  # idempotent: duplicate id is not stored twice
    with RECEIPTS.open("a") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")
        fh.flush()
        os.fsync(fh.fileno())
    return True


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._send(200, {"status": "ok", "receipts": len(_load())})
            return
        if self.path == "/receipts":
            self._send(200, {"receipts": _load()})
            return
        if self.path.startswith("/receipts/"):
            rid = self.path.split("/receipts/", 1)[1].split("?")[0]
            for r in _load():
                if r.get("id") == rid:
                    self._send(200, r)
                    return
            self._send(404, {"error": "not found"})
            return
        self._send(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/receipts":
            self._send(404, {"error": "not found"})
            return
        try:
            rec = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or "{}")
        except (ValueError, json.JSONDecodeError):
            self._send(400, {"error": "bad json"})
            return
        if not isinstance(rec, dict) or not rec.get("id"):
            self._send(400, {"error": "receipt requires an 'id'"})
            return
        created = _append(rec)
        self._send(201 if created else 200, {"stored": rec["id"], "created": created})

    def log_message(self, format: str, *args: object) -> None:
        pass  # keep stub logs quiet


if __name__ == "__main__":
    STORE.mkdir(parents=True, exist_ok=True)
    HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
