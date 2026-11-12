"""Hash-chained receipt ledger for the hosted operator surface (R2 slice 1).

The hosted surfaces hold no gateway signer in-process, so session lifecycle
and role changes are receipted as append-only, hash-chained ledger entries in
a sidecar file (never inside the evidence store, never in the demo data).
Each line:

    {"index": N, "at": "<ISO-8601 UTC>", "action": "<kind>",
     "payload": {...}, "prev_hash": "<previous digest | null>",
     "hash": "<sha256 over the canonical JSON of this row minus 'hash'>"}

Tamper-evidence is the same discipline the index plane applies to chained
receipts: any edit to a row invalidates every digest after it; a new file
appended to (chain head mismatch) or rewritten history fails ``load`` fail-
closed. The chain head is verified against the stored rows on reload, so a
truncated or re-ordered file cannot pass as continuous.

Receipt semantics mirror the gateway admin session idiom (X3 slice 1 in the
raucle repository): session open/close/refresh and role changes are recorded
BEFORE the state transition is observable, never silently; a signed receipt
identifies the action, the actor session's public handle (never a bearer
token) and the bound expiry. Wired to a real JWS signer is the follow-up
named in the PR; until then this chain is the receipt of record for the
hosted surface.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import pathlib

logger = logging.getLogger(__name__)

LEDGER_KIND = "oaa_hosted_ledger"
LEDGER_VERSION = 1


class LedgerCorruptError(Exception):
    """The stored chain is damaged (truncated, re-ordered or edited)."""


def canonical_json(value) -> str:
    """Byte-stable JSON for hashing (sorted keys, compact separators)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class HostedReceiptLedger:
    """Append-only hashed receipt chain in one JSONL sidecar file."""

    def __init__(self, path: pathlib.Path, *, clock=datetime.datetime.now) -> None:
        self.path = pathlib.Path(path)
        self._clock = clock
        self._index = -1
        self._head: str | None = None
        self._entries: list[dict] = []

    # ------------------------------------------------------------ lifecycle
    def load(self) -> HostedReceiptLedger:
        """Load (or initialise) the chain, verifying continuity fail-closed."""
        self._index = -1
        self._head = None
        self._entries = []
        if not self.path.exists():
            # First boot: create the meta line; later appends make parents.
            return self._write_meta()
        total = 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            total += 1
            row = json.loads(line)
            if row.get("index") != total - 1:
                raise LedgerCorruptError(
                    f"ledger {self.path.name}: expected row index {total - 1},"
                    f" found {row.get('index')!r}"
                )
            if row.get("prev_hash") != self._head:
                raise LedgerCorruptError(
                    f"ledger {self.path.name}: row {row.get('index')} does not"
                    " chain onto the previous digest"
                )
            if row.get("hash") != _row_hash(row):
                raise LedgerCorruptError(
                    f"ledger {self.path.name}: row {row.get('index')} digest mismatch"
                )
            self._head = row["hash"]
            self._index = total - 1
            self._entries.append(row)
        if not self._entries:
            return self._write_meta()
        return self

    def _write_meta(self) -> HostedReceiptLedger:
        if self._entries:
            return self
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._append_line(
            {
                "index": 0,
                "at": _iso(self._clock()),
                "action": LEDGER_KIND,
                "payload": {"version": LEDGER_VERSION},
                "prev_hash": None,
            }
        )
        return self

    # ------------------------------------------------------------ appending
    def append(self, action: str, payload: dict) -> dict:
        """Append one receipt; returns the stored row. Never silent."""
        return self._append_line(
            {
                "index": self._index + 1,
                "at": _iso(self._clock()),
                "action": action,
                "payload": dict(payload),
                "prev_hash": self._head,
            }
        )

    def _append_line(self, base: dict) -> dict:
        base["hash"] = _row_hash(base)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(base, sort_keys=True) + "\n")
        self._head = base["hash"]
        self._index = base["index"]
        self._entries.append(base)
        return dict(base)

    # ------------------------------------------------------------ read-back
    def entries(self, action: str | None = None) -> list[dict]:
        """All rows (optionally one action kind); used by tests and replay."""
        if action is None:
            return [dict(e) for e in self._entries]
        return [dict(e) for e in self._entries if e.get("action") == action]

    def head(self) -> str | None:
        return self._head


def _iso(moment: datetime.datetime) -> str:
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=datetime.UTC)
    return moment.isoformat().replace("+00:00", "Z")


def _row_hash(row: dict) -> str:
    material = {k: v for k, v in row.items() if k != "hash"}
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()
