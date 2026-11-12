"""Open Agent Assurance — UI-01 investigation UI demo data.

Loads the demo data dir (read-only, invariant 1):

- ``evidence_store.jsonl``  canonical ``{receipt_hash, jws}`` envelopes (copy
  of the obs01 spike store, sha256 0afe93c937b96c... — recorded in README).
- ``synthetic_receipt_index.jsonl`` hand-built INDEX rows (explicit
  ``synthetic: true``, fake hashes) exercising duplicate / ambiguous /
  late_arrival correlation states.
- ``runs.json`` run/trace/span fixture (includes hostile attribute values —
  XSS and javascript:-link probes — covered by threat model T5 tests).
- ``verification_index.jsonl`` per-receipt verification status rows (index
  plane only; the UI never re-verifies at rest).
- ``trust_roots.jsonl`` trust roots for the offline verifier (public half
  only; raucle 0.23.5 wants ``dict[str, bytes]``, hence bytes-encoded PEMs).
- ``rules_fixture.json`` documented suppressions for the RULE-01 findings
  panel (suppressed findings are retained, never dropped).
- ``synthetic_audit_events.jsonl`` UI-02.4: hand-built audit-plane INDEX
  rows (tool audits, custody, identity chains, ingest coverage) — every
  row carries ``synthetic: true``: explicit, honest synthetic markers that
  make all eleven SEC rules fire somewhere in the demo corpus.

Correlation index rows are computed at load time with the COR-01 engine
(``oaa_correlation.reconcile``) from the receipt-side index (real receipts
decoded for trace_id/decision/event_time + the synthetic rows) against
trace-side records built from the fixture — index-plane only; canonical
bytes never leave ``evidence_store.jsonl``.

The private key of the trust roots lives with the spike directory and is
NEVER copied here; only the derived public half is.
"""
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import pathlib
import sys

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[4]
for _src in (
    _REPO_ROOT / "packages" / "raucle-adapter" / "src",
    _REPO_ROOT / "services" / "correlation" / "src",
    _REPO_ROOT / "services" / "rules" / "src",
):
    if _src.is_dir() and str(_src) not in sys.path:
        # Same importability convention as the repo root conftest.py.
        sys.path.insert(0, str(_src))

from oaa_correlation import (  # noqa: E402
    ReceiptRecord,
    TraceRecord,
    reconcile,
)
from oaa_raucle_adapter.evidence_plane import (  # noqa: E402
    TrustRoot,
    TrustRootRegistry,
)

VERIFICATION_STATES = (
    "valid",
    "invalid",
    "unknown_key",
    "unsupported_schema",
    "pending",
    "unavailable",
    "not_applicable",
)

# Explicit-unknown states styled distinctly in the UI (threat model T5 /
# plan: unknown never renders silently blank).
UNKNOWN_STATES = frozenset({"unknown_key", "unsupported_schema", "pending", "unavailable"})

NO_RECEIPT_STATE = "unavailable"  # explicit, never blank — "no receipt observed"


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _as_utc(x: str) -> str:
    return dt.datetime.fromisoformat(x).astimezone(dt.UTC).isoformat()


def _sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class DemoData:
    """Immutable, load-time snapshot of the demo investigation data."""

    def __init__(self, data_dir: pathlib.Path) -> None:
        self.dir = pathlib.Path(data_dir)
        self._store_lines: list[str] = []
        self._store_index: dict[str, int] = {}
        self._receipt_meta: dict[str, dict] = {}
        self._verif: dict[str, dict] = {}
        self.runs: list[dict] = []
        self._spans: dict[str, dict] = {}
        self.correlation_by_trace: dict[str, dict] = {}
        self.correlation_by_hash: dict[str, dict] = {}
        self._expected_correlation_overrides: dict[str, str] = {}
        self.warnings: list[str] = []

        self._load_evidence_store()
        self._load_verification_index()
        self._load_runs()
        self._load_audit_events()
        self._correlate()
        self.findings = self._rules()

    # ------------------------------------------------------------------ load
    def _load_evidence_store(self) -> None:
        path = self.dir / "evidence_store.jsonl"
        before = _sha256_bytes(path.read_bytes())
        raw = path.read_bytes()
        if before != _sha256_bytes(raw):
            raise RuntimeError(f"evidence store {path} changed during read-only load")
        for i, line_bytes in enumerate(raw.splitlines()):
            line = line_bytes.decode()
            if not line.strip():
                continue
            rec = json.loads(line)
            if set(rec) != {"receipt_hash", "jws"}:
                raise ValueError(f"canonical line {i} is not an envelope: {sorted(rec)}")
            self._store_lines.append(line)
            self._store_index[rec["receipt_hash"]] = len(self._store_lines) - 1
            payload = json.loads(_b64d(rec["jws"].split(".")[1]))
            gate = payload.get("x_gate", {})
            iat = int(payload.get("iat", 0))
            self._receipt_meta[rec["receipt_hash"]] = {
                "receipt_hash": rec["receipt_hash"],
                "schema_version": payload.get("typ", ""),
                "decision": gate.get("decision"),
                "policy_ref": gate.get("policy"),
                "tool": gate.get("tool"),
                "trace_id": gate.get("trace_id"),
                "event_time": dt.datetime.fromtimestamp(iat, dt.UTC).isoformat() if iat else None,
                "jws_available": True,
                "canonical": True,
            }

    def _load_verification_index(self) -> None:
        for line in (self.dir / "verification_index.jsonl").read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            row = json.loads(line)
            if row["status"] not in VERIFICATION_STATES:
                raise ValueError(f"bad verification status {row['status']!r}")
            self._verif[row["receipt_hash"]] = row

    def _receipt_index_rows(self, synthetic_path: pathlib.Path) -> list[ReceiptRecord]:
        rows: list[ReceiptRecord] = []
        # Confinement: the synthetic index path is derived from the (possibly
        # env-sourced) data directory, so the resolved path must stay inside
        # that directory before anything is read from it.
        base_r = pathlib.Path(self.dir).resolve()
        path_r = pathlib.Path(synthetic_path).resolve()
        if not path_r.is_relative_to(base_r):
            raise ValueError(
                f"synthetic index {str(path_r)!s} is outside the demo data dir "
                f"{str(base_r)!s}; refusing to read it"
            )
        rows.extend(self._real_receipt_rows())
        # Synthetic index rows (explicit markers). Read via the resolved,
        # confined path rather than the raw caller-supplied one.
        for line in path_r.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rows.append(self._synthetic_row(json.loads(line)))
        return rows

    def _real_receipt_rows(self) -> list[ReceiptRecord]:
        """Evidence-store receipts: index fields decoded from the signed payload."""
        return [
            ReceiptRecord(
                receipt_hash=meta["receipt_hash"],
                trace_id=meta["trace_id"],
                decision=meta["decision"],
                event_time=dt.datetime.fromisoformat(meta["event_time"]),
                provenance="evidence_store.jsonl",
                gate_id=meta.get("gate_id") or "gateway",
            )
            for meta in self._receipt_meta.values()
        ]

    def _synthetic_row_correlation_override(self, row: dict) -> None:
        """UI-02.4: the ONLY supported expected_correlation value is
        matched_degraded — a hand-built fallback-pairing demo over a row
        that would otherwise reconcile to exactly `matched`."""
        expected = row.get("expected_correlation")
        if not expected:
            return
        if expected != "matched_degraded":
            raise ValueError("expected_correlation override only supports matched_degraded")
        self._expected_correlation_overrides[row.get("trace_id")] = expected

    def _synthetic_meta(self, row: dict) -> dict:
        return {
            "receipt_hash": row["receipt_hash"],
            "schema_version": row.get("schema_version", ""),
            "decision": row.get("decision"),
            "policy_ref": row.get("policy_ref"),
            "tool": row.get("tool"),
            "trace_id": row.get("trace_id"),
            "event_time": row["event_time"],
            "jws_available": False,
            "canonical": False,
        }

    def _synthetic_row(self, row: dict) -> ReceiptRecord:
        """Validate + build one synthetic-index receipt record."""
        if not row.get("synthetic"):
            raise ValueError("synthetic index rows must set synthetic: true")
        if row["receipt_hash"] in self._store_index:
            raise ValueError("synthetic row must never collide with canonical store")
        self._receipt_meta[row["receipt_hash"]] = self._synthetic_meta(row)
        self._synthetic_row_correlation_override(row)
        return ReceiptRecord(
            receipt_hash=row["receipt_hash"],
            trace_id=row.get("trace_id"),
            decision=row.get("decision"),
            event_time=dt.datetime.fromisoformat(row["event_time"]),
            provenance=row.get("provenance"),
            synthetic=True,
        )

    def _load_audit_events(self) -> None:
        """UI-02.4: audit-plane synthetic rows (kind tool_audit / custody /
        identity / ingest). Each row must be explicitly ``synthetic``; the
        ``content`` field (SEC-008 probe material) is held ONLY for the rules
        engine's pattern check and is never copied into any finding or any
        API response (PRIV-01: presence, not payload)."""
        self._audit_events: list[dict] = []
        path = self.dir / "synthetic_audit_events.jsonl"
        if not path.is_file():
            return
        for i, line in enumerate(path.read_text().splitlines()):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            row = json.loads(line)
            if not row.get("synthetic"):
                raise ValueError(f"audit event row {i} must set synthetic: true")
            row = dict(row.items())
            self._audit_events.append(row)

    def _audit_engine_events(self) -> list:
        """Project audit rows into the rules engine's Event model. The raw
        row (including ``content``) never leaves this module."""
        import datetime as _dt  # noqa: PLC0415

        from oaa_rules import Event  # noqa: PLC0415

        events: list[Event] = []
        for row in self._audit_events:
            fields = {
                k: row[k]
                for k in (
                    "ref",
                    "agent_id",
                    "tool",
                    "application",
                    "trace_id",
                    "receipt_hash",
                    "state",
                    "decision",
                    "outcome",
                    "privileged",
                    "credential_id",
                    "action",
                    "lease_id",
                    "release_id",
                    "chain_seq",
                    "producer_id",
                    "content",
                )
                if k in row
            }
            events.append(
                Event(kind=row["kind"], at=_dt.datetime.fromisoformat(row["at"]), **fields)
            )
        return events

    def _load_runs(self) -> None:
        self.runs = json.loads((self.dir / "runs.json").read_text())["runs"]
        for run in self.runs:
            for trace in run["traces"]:
                for span in trace["spans"]:
                    self._spans[span["span_id"]] = span

    def _correlate(self) -> None:
        receipts = self._receipt_index_rows(self.dir / "synthetic_receipt_index.jsonl")
        traces = [
            TraceRecord(
                trace_id=t["trace_id"],
                tool_invocation=next((s["tool"] for s in t["spans"] if s.get("privileged")), None),
                observed_at=dt.datetime.fromisoformat(t["window_start"]),
                window_start=dt.datetime.fromisoformat(t["window_start"]),
                window_end=dt.datetime.fromisoformat(t["window_end"]),
                agent=run.get("agent"),
                # type: ignore[arg-type]  # observed_at unused when windows set
            )
            for run in self.runs
            for t in run["traces"]
        ]
        # Coverage (R1) reads the same receipt/trace index plane the engine
        # reconciled: retained read-only, engine states, UI overrides aside.
        self.receipt_records: list[ReceiptRecord] = receipts
        self.trace_records: list[TraceRecord] = traces
        result = reconcile(receipts, traces, at=None)
        for record in result.records:
            # UI-02.4: hand-built fallback-pairing demo rows may declare
            # expected_correlation == "matched_degraded" — an explicit,
            # honest override of the state (the COR-01 engine has no
            # fallback keys yet; see note in the spike). Notes always
            # carry the hand-built marker so the override is visible.
            override = self._expected_correlation_overrides.get(record.trace_id)
            state = record.state
            notes = record.notes
            if override:
                state = override
                notes = (
                    f"hand-built matched_degraded demo case (UI-02.4); prior state: {record.state}"
                )
            payload = {
                "state": state,
                "trace_id": record.trace_id,
                "receipt_hashes": list(record.receipt_hashes),
                "decision": record.decision,
                "notes": notes,
                "provenance": list(record.provenance),
                "receipt_event_times": [e.isoformat() for e in record.receipt_event_times],
                "trace_observed_at": record.trace_observed_at.isoformat()
                if record.trace_observed_at
                else None,
                "pending": False,
            }
            for h in record.receipt_hashes:
                self.correlation_by_hash[h] = payload
            if record.trace_id:
                self.correlation_by_trace[record.trace_id] = payload
        self.pending_count = result.pending

    # --------------------------------------------------------------- rules
    def _rules(self) -> list[dict]:
        from oaa_rules import (  # noqa: PLC0415
            Event,
            run_rules,
        )

        fixture = json.loads((self.dir / "rules_fixture.json").read_text())
        config = self.demo_rules_config(fixture)
        events: list[Event] = []
        for payload in {p["trace_id"]: p for p in self.correlation_by_trace.values()}.values():
            events.append(
                Event(
                    kind="correlation",
                    ref=payload["trace_id"],
                    at=dt.datetime.fromisoformat(
                        payload["trace_observed_at"] or "1970-01-01T00:00:00+00:00"
                    ),
                    trace_id=payload["trace_id"],
                    state=payload["state"],
                    decision=payload["decision"],
                    tool=next(
                        (
                            s["tool"]
                            for run in self.runs
                            for t in run["traces"]
                            if t["trace_id"] == payload["trace_id"]
                            for s in t["spans"]
                            if s.get("privileged")
                        ),
                        None,
                    ),
                )
            )
        for row in self._verif.values():
            events.append(
                Event(
                    kind="verification",
                    at=dt.datetime.fromisoformat(row["checked_at"]),
                    ref=row["receipt_hash"],
                    receipt_hash=row["receipt_hash"],
                    state=row["status"],
                )
            )
        findings = run_rules([*events, *self._audit_engine_events()], config)
        return [
            {**base, **self._finding_meta(base)}
            for base in (self._finding_dict(f) for f in findings)
        ]

    def _finding_dict(self, f) -> dict:
        return {
            "rule_id": f.rule_id,
            "rule_version": f.rule_version,
            "severity": f.severity,
            "confidence": f.confidence,
            "evidence_refs": list(f.evidence_refs),
            "explanation": f.explanation,
            "subject": f.subject,
            "suppressed": f.suppression_reason is not None,
            "suppression_reason": f.suppression_reason,
        }

    def demo_rules_config(self, fixture) -> dict:
        """Demo rules config (UI-02.4): same engine, but the demo corpus is
        deliberately designed to exercise every rule. Registry coverage and
        thresholds stay engine defaults; the demo enables the release
        baseline, one custody-covered tool and the documented suppressions."""
        from oaa_rules import RulesConfig, Suppression  # noqa: PLC0415

        return RulesConfig(
            tool_baseline={"rel-0.9.3": frozenset({"shell", "file_write"})},
            custody_covered_tools=frozenset({"vault_read"}),
            suppressions=tuple(
                Suppression(
                    rule_id=s["rule_id"],
                    reason=s["reason"],
                    trace_id=s.get("trace_id"),
                )
                for s in fixture.get("suppressions", [])
            ),
        )

    def _finding_meta(self, base: dict) -> dict:
        """UI-02.4 board metadata per finding: stable id, detection instant
        (the audit-event time when the primary evidence ref is an audit
        record, else the earliest correlated receipt / check time) and the
        demo run the finding belongs to (None for corpus-level findings)."""
        refs = set(base["evidence_refs"])
        trace_ids = {t["trace_id"] for r in self.runs for t in r["traces"] for t in [t]}
        run_id = self._finding_run_id(refs)
        detected = self._finding_detection_time(base)
        return {
            "id": self._finding_id(base),
            "detected_at": detected,
            "run_id": run_id,
            "trace_ids_only": None if not refs & trace_ids else sorted(refs & trace_ids),
        }

    def _finding_run_id(self, refs: set[str]) -> str | None:
        """The demo run the finding belongs to (None for corpus-level)."""
        run_hashes = {
            s["receipt_hash"]: r["run_id"]
            for r in self.runs
            for tr in r["traces"]
            for s in tr["spans"]
            if s["receipt_hash"]
        }
        audit_by_ref = {e["ref"]: e for e in self._audit_events}
        expanded = set(refs)
        for ref in refs:
            if ref in audit_by_ref and audit_by_ref[ref].get("trace_id"):
                expanded.add(audit_by_ref[ref]["trace_id"])
        for r in self.runs:
            local = {t["trace_id"] for t in r["traces"]}
            if expanded & local or any(
                h in run_hashes and run_hashes[h] == r["run_id"] for h in refs
            ):
                return r["run_id"]
        return None

    def _finding_detection_time(self, base: dict):
        """Detection instant: the audit-event time when the primary evidence
        ref is an audit record, else the earliest correlated receipt/check
        time."""
        audit_by_ref = {e["ref"]: e for e in self._audit_events}
        for ref in base["evidence_refs"]:
            if ref in audit_by_ref:
                return audit_by_ref[ref]["at"]
        for ref in base["evidence_refs"]:
            payload = self.correlation_by_trace.get(ref) or self.correlation_by_hash.get(ref)
            if payload:
                times = payload.get("receipt_event_times") or []
                obs = payload.get("trace_observed_at")
                if times or obs:
                    return min(x for x in [*(times or []), obs] if x)
        return None

    def _finding_id(self, base: dict) -> str:
        """Stable, deterministic finding id for board triage state keys."""
        seed = base["rule_id"] + "|" + "|".join(base["evidence_refs"]) + "|" + base["explanation"]
        return "f-" + hashlib.sha256(seed.encode()).hexdigest()[:12]

    # ---------------------------------------------------------------- access
    def get_run(self, run_id: str) -> dict | None:
        return next((r for r in self.runs if r["run_id"] == run_id), None)

    def correlation_for_span(self, span: dict, trace_id: str | None = None) -> dict:
        """Explicit correlation payload for a span — never a blank state."""
        trace_id = trace_id or ""
        h = span.get("receipt_hash")
        if h and h in self.correlation_by_hash:
            return self.correlation_by_hash[h]
        if h and trace_id in self.correlation_by_trace:
            return self.correlation_by_trace[trace_id]
        if h is None and self.correlation_by_trace.get(trace_id, {}).get("state") == (
            "receipt_missing"
        ):
            # receipt-side absence attaches to spans of the same trace.
            return self.correlation_by_trace[trace_id]
        return {
            "state": "pending",
            "trace_id": trace_id or None,
            "receipt_hashes": [h] if h else [],
            "decision": None,
            "notes": "no terminal correlation record for this span (in-grace / open)",
            "provenance": [],
            "receipt_event_times": [],
            "trace_observed_at": None,
            "pending": True,
        }

    def verification_for(self, receipt_hash: str | None) -> dict:
        if receipt_hash is None:
            return {
                "status": NO_RECEIPT_STATE,
                "detail": "no gate receipt observed for this span (absence is a "
                "coverage gap, not a result)",
                "recorded": False,
                "explicit_unknown": True,
            }
        row = self._verif.get(receipt_hash)
        if row is None:
            return {
                "status": "unavailable",
                "detail": "no verification record at ingest time",
                "recorded": False,
                "explicit_unknown": True,
            }
        return {
            "status": row["status"],
            "detail": row["detail"],
            "checked_at": row["checked_at"],
            "recorded": True,
            "explicit_unknown": row["status"] in UNKNOWN_STATES,
        }

    def receipt_meta(self, receipt_hash: str) -> dict | None:
        return self._receipt_meta.get(receipt_hash)

    def store_line(self, receipt_hash: str) -> str | None:
        i = self._store_index.get(receipt_hash)
        return None if i is None else self._store_lines[i]

    def trust_roots(self) -> TrustRootRegistry:
        reg = TrustRootRegistry()
        for line in (self.dir / "trust_roots.jsonl").read_text().splitlines():
            if not line.strip() or line.startswith("#"):
                continue
            row = json.loads(line)
            # raucle 0.23.5 ProvenanceVerifier expects dict[str, bytes] PEMs.
            reg.add(
                TrustRoot(
                    row["key_id"],
                    row["public_key_pem"].encode(),  # type: ignore[arg-type]
                    row["valid_from"],
                    row["valid_until"],
                    row.get("status", "current"),
                )
            )
        return reg


def default_data_dir() -> pathlib.Path:
    import os  # noqa: PLC0415

    env = os.environ.get("OAA_INVESTIGATION_UI_DATA")
    if env:
        # The value comes from the environment, so resolve it and refuse
        # unusable targets before it can seed any file access downstream.
        resolved = pathlib.Path(env).expanduser().resolve()
        if resolved == pathlib.Path(resolved.root) or resolved == pathlib.Path.home():
            raise SystemExit(
                f"refusing OAA_INVESTIGATION_UI_DATA={env!s}: "
                "resolves to an unusable data directory"
            )
        return resolved
    return pathlib.Path(__file__).resolve().parents[2] / "demo_data"
