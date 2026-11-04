# SPDX-License-Identifier: Apache-2.0
"""Open Agent Assurance — AUD-01 auditor export pack (P1.7a).

Compiles a self-contained regulator/auditor export pack from a bounded
query window over the read-only evidence store (canonical ``{receipt_hash,
jws}`` JSONL, ADR-0001). The pack is a directory plus ``.zip``; it contains
everything a reviewer needs to verify offline and nothing else:

- ``receipts.jsonl``  — byte-exact JWS envelope lines for the window;
- ``keys/``           — the trust-root key snapshot (public halves only, verbatim);
- ``timestamps/``     — RFC 3161 anchor tokens extracted from receipts that
  carry them; ships an honest absence note when the window has none;
- ``policies/``       — policy files plus their deployment-chain receipts
  when the gate audit is accessible; an explicit absence note otherwise;
- ``chain_graph.json``— reserved slot, currently ``pending P1.1a wire-up``
  (the pack manifest is additive: this file may gain graph content in
  place without breaking the contract);
- ``claims.md``       — plain-English claim sheet via the GOV-01
  honest-report pattern, with the mandatory no-claim guard section;
- ``manifest.json``   — sha256 of every file above (``file -> sha256``);
- ``verify-notes.md`` — offline verification instructions for the reviewer.

The pack NEVER makes a compliance claim: ``claims.md`` is generated with
the same structural no-claim guard as the GOV-01 report, and the guard is
itself a checked pack invariant (the standalone verifier warns when absent).

Nothing in this module reads the canonical JWS into any report text —
envelopes are copied verbatim or referenced by digest only.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import sys
import zipfile

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]


def _load_repo_module(name: str, rel_path: str):
    """Import a repo module by file path (the on-disk dir 'audit-pack'
    contains a hyphen, so this subtree is not a package identifier)."""
    path = pathlib.Path(__file__).resolve().parents[1] / rel_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None, f"module spec not found: {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# The GOV-01 honest-report generator supplies the shared structural
# no-claim guard; loaded by path for the same hyphen-in-directory reason.
_generate_report = _load_repo_module(
    "oaa_gov01_generate_report", os.path.join("assurance", "generate_report.py")
)
assert_no_compliance_claims = _generate_report.assert_no_compliance_claims

PACK_SCHEMA_VERSION = 1

# Sentinel the standalone verifier looks for in claims.md. Both the header
# and the sentence are contract: a claim sheet without BOTH is a warning.
GUARD_HEADER = "## Mandatory no-claim guard"
GUARD_SENTINEL = (
    "This pack records what was cryptographically observed inside a"
    " deliberately narrow scope. It does not establish legal or regulatory"
    " compliance, and it asserts no certification, no approval, no"
    " accreditation, no attestation, and no warranty of any kind."
)

CHAIN_GRAPH_PENDING = "pending P1.1a wire-up"

ZIP_NAME = "audit-pack.zip"


# ------------------------------------------------------------------------


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def _now_iso() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


def _sha256_file(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _envelope_payload(envelope_line: str) -> dict:
    """Decode the signed payload of a canonical envelope line."""
    jws = json.loads(envelope_line)["jws"]
    return json.loads(_b64d(jws.split(".")[1]))


def _event_time(envelope_line: str) -> dt.datetime:
    """Event time of an envelope: its signed ``iat`` (event-time rule)."""
    return dt.datetime.fromtimestamp(int(_envelope_payload(envelope_line)["iat"]), tz=dt.UTC)


# --------------------------------------------------------------- select ----


def select_envelopes(
    store_path: pathlib.Path,
    *,
    from_utc: dt.datetime | None = None,
    to_utc: dt.datetime | None = None,
    receipt_hash: str | None = None,
) -> list[str]:
    """Byte-exact envelope lines from the bounded query window.

    A single ``receipt_hash`` selects exactly one envelope and ignores the
    window (explicit single-receipt mode). Otherwise the window is the
    signed ``iat`` of each envelope; unknown/undecodable lines are skipped
    with a stderr note, never silently dropped or repaired.
    """
    if receipt_hash is not None:
        lines = store_path.read_text(encoding="utf-8").splitlines()
        for line in lines:
            line = line.rstrip("\n")
            if not line:
                continue
            rec = json.loads(line)
            if rec["receipt_hash"] == receipt_hash:
                return [line]
        raise FileNotFoundError(f"{receipt_hash} not in evidence store {store_path}")

    out: list[str] = []
    for raw in store_path.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip("\n")
        if not line:
            continue
        try:
            t = _event_time(line)
        except Exception as exc:
            print(f"audit-pack: skipped undecodable store line: {exc}", file=sys.stderr)
            continue
        if from_utc is not None and t < from_utc:
            continue
        if to_utc is not None and t > to_utc:
            continue
        out.append(line)
    return out


# ------------------------------------------------------------- claims ------


def build_claim_sheet(
    *, window: str, receipts: int, keys: int, timestamp_tokens: int,
    policies: str, chain_graph: str, clock: dt.datetime | None = None,
) -> str:
    """Plain-English claim sheet, GOV-01 honest-report pattern.

    States only what the pack contains; the no-claim guard is a mandatory
    fixed section. Raises ValueError (via the shared guard) if any line
    states a banned claim in positive context — the generator can never
    emit one.
    """
    now = (clock or dt.datetime.now(dt.UTC)).isoformat()
    lines = [
        "# Receipt-claim sheet (AUD-01 auditor export pack)",
        "",
        f"Generated: {now}",
        f"Query window: {window}",
        "",
        "## What this pack contains",
        "",
        f"- **{receipts}** receipt envelope(s), copied byte-exactly into `receipts.jsonl`.",
        f"- A trust-root snapshot of **{keys}** public signing key(s) (public halves",
        "  only — no private key material exists in this pack) under `keys/`.",
        f"- **{timestamp_tokens}** RFC 3161 timestamp token(s) extracted into `timestamps/`.",
        f"- Policy evidence: {policies}",
        f"- Chain-graph slot: {chain_graph}",
        "- This file (`claims.md`), a `manifest.json` of per-file sha256 digests, and",
        "  `verify-notes.md` telling you how to check all of it, offline.",
        "",
        "## What you can check with this pack",
        "",
        "- That every packed file matches its recorded sha256 digest (the manifest) —",
        "  this detects post-export tampering.",
        "- That each receipt's receipt_hash re-derives from its JWS bytes.",
        "- That each receipt's Ed25519 signature validates against the embedded key",
        "  snapshot, within that key's stated validity window (trust policy",
        "  `evd-trust-1`: integrity and authority only — nothing further).",
        "- That receipts which claim an RFC 3161 anchor carry the matching token.",
        "",
        "## What this pack does NOT contain",
        "",
        "- Any private key. Verification is genuinely offline.",
        "- Evidence from outside the query window (unsampled sinks, prior retention",
        "  windows, ungated paths). Absence here is not absence everywhere — the",
        "  boundary above is the whole scope.",
        "",
        GUARD_HEADER,
        "",
        GUARD_SENTINEL,
        "",
        "No statement in this pack, and no receipt in it, may be read as advice",
        "about safety, appropriateness, or any regulated outcome.",
        "",
    ]
    text = "\n".join(lines)
    assert_no_compliance_claims(text)  # self-guard: never emit a claim
    return text


# -------------------------------------------------------------- build ------


def build_pack(
    evidence_store: pathlib.Path,
    trust_roots: pathlib.Path,
    out_dir: pathlib.Path,
    *,
    from_utc: dt.datetime | None = None,
    to_utc: dt.datetime | None = None,
    receipt_hash: str | None = None,
    policies_dir: pathlib.Path | None = None,
    policy_receipt_hashes: list[str] | None = None,
    clock: dt.datetime | None = None,
) -> dict:
    """Build the pack directory (and its ``.zip``); return a summary dict.

    Deterministic for fixed inputs and a fixed injected clock (used for
    ``claims.md`` and manifest timestamps).
    """
    evidence_store = pathlib.Path(evidence_store)
    trust_roots = pathlib.Path(trust_roots)
    out_dir = pathlib.Path(out_dir)
    if out_dir.exists():
        shutil.rmtree(out_dir)

    envelopes = select_envelopes(
        evidence_store, from_utc=from_utc, to_utc=to_utc, receipt_hash=receipt_hash
    )
    pack = out_dir / "audit-pack"
    pack.mkdir(parents=True)

    # receipts.jsonl — canonical byte-exact envelope lines.
    (pack / "receipts.jsonl").write_text("\n".join(envelopes) + "\n", encoding="utf-8")

    # keys/ — verbatim trust-root snapshot (public halves only).
    keys_dir = pack / "keys"
    keys_dir.mkdir()
    shutil.copyfile(trust_roots, keys_dir / trust_roots.name)
    n_keys = sum(1 for ln in trust_roots.read_text().splitlines() if ln.strip())

    # timestamps/ — extract RFC 3161 tokens from envelopes that claim one.
    ts_dir = pack / "timestamps"
    ts_dir.mkdir()
    token_count = 0
    for line in envelopes:
        x_ts = _envelope_payload(line).get("x_timestamp")
        if isinstance(x_ts, dict) and x_ts.get("token"):
            token = _b64d(str(x_ts["token"]))
            rh = json.loads(line)["receipt_hash"].replace(":", "-")
            (ts_dir / f"{rh}.token").write_bytes(token)
            token_count += 1
    if token_count == 0:
        (ts_dir / "README.md").write_text(
            "# Timestamps\n\n"
            "No receipt in this window carries an RFC 3161 timestamp anchor.\n"
            "This is an honest absence, not a failure: receipts verified at\n"
            "event time on the host clock still carry their signed `iat`, and\n"
            "the claim sheet states exactly this scope.\n",
            encoding="utf-8",
        )

    # policies/ — policy files + deployment-chain receipts, degrade honestly.
    pol_dir = pack / "policies"
    pol_dir.mkdir()
    copied_policies: list[str] = []
    if policies_dir is not None:
        policies_dir = pathlib.Path(policies_dir)
        for f in sorted(policies_dir.iterdir()):
            if f.is_file() and f.suffix in {".yaml", ".yml", ".json"}:
                shutil.copyfile(f, pol_dir / f.name)
                copied_policies.append(f.name)
    if policy_receipt_hashes:
        pol_lines: list[str] = []
        store_all = [
            ln.rstrip("\n")
            for ln in evidence_store.read_text(encoding="utf-8").splitlines()
            if ln.strip()
        ]
        by_hash = {json.loads(ln)["receipt_hash"]: ln for ln in store_all}
        for rh in policy_receipt_hashes:
            if rh in by_hash:
                pol_lines.append(by_hash[rh])
        (pol_dir / "deployment_chain_receipts.jsonl").write_text(
            "\n".join(pol_lines) + "\n", encoding="utf-8"
        )
    if copied_policies and policy_receipt_hashes:
        policies_note = f"{len(copied_policies)} policy file(s) and deployment-chain receipts under `policies/`"
    elif copied_policies:
        policies_note = (
            f"{len(copied_policies)} policy file(s) under `policies/`; deployment-chain"
            " receipts were not accessible at pack time — this is stated, not hidden"
        )
        (pol_dir / "README.md").write_text(
            "# Policies\n\nDeployment-chain receipts from the gate audit were not\n"
            "accessible at pack time. Policy files are included verbatim; the\n"
            "deployment chain for them is unverified — treated honestly as a gap,\n"
            "never as evidence of approval.\n",
            encoding="utf-8",
        )
    else:
        policies_note = (
            "not included — the policy set and its deployment-chain receipts were"
            " not accessible at pack time; coverage here is unverified"
        )
        (pol_dir / "README.md").write_text(
            "# Policies\n\nNot included: no policy file or deployment-chain receipt\n"
            "was accessible at pack time. The pack does not claim policy coverage\n"
            "it cannot show. Obtain the current policy set from the operator\n"
            "separately and verify it against the gate-audit records.\n",
            encoding="utf-8",
        )

    # chain_graph.json — reserved, additive slot (P1.1a dependency).
    (pack / "chain_graph.json").write_text(
        json.dumps(
            {
                "schema_version": PACK_SCHEMA_VERSION,
                "status": CHAIN_GRAPH_PENDING,
                "note": "chain resolution is being built in P1.1a; this slot is reserved and additive — a future pack fills it in place without changing the manifest contract",
                "edges": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    # claims.md — honest-report pattern, no-claim guard preserved.
    if receipt_hash is not None:
        window = f"single receipt {receipt_hash}"
    else:
        lo = min((_event_time(ln) for ln in envelopes), default=None)
        hi = max((_event_time(ln) for ln in envelopes), default=None)
        window = f"{lo.isoformat() if lo else '…'} .. {hi.isoformat() if hi else '…'} (event time, signed iat)"
    claims = build_claim_sheet(
        window=window,
        receipts=len(envelopes),
        keys=n_keys,
        timestamp_tokens=token_count,
        policies=policies_note,
        chain_graph=f"`chain_graph.json` is reserved and currently {CHAIN_GRAPH_PENDING}.",
        clock=clock,
    )
    (pack / "claims.md").write_text(claims, encoding="utf-8")

    # verify-notes.md — reviewer instructions.
    (pack / "verify-notes.md").write_text(
        _verify_notes(receipts=len(envelopes),
                      timestamps=token_count,
                      policies=policies_note),
        encoding="utf-8",
    )

    # manifest.json — sha256 of every file so far (itself excluded; written last).
    files = {
        str(p.relative_to(pack)): _sha256_file(p) for p in sorted(pack.rglob("*")) if p.is_file()
    }
    now = (clock or dt.datetime.now(dt.UTC)).replace(microsecond=0)
    manifest = {
        "schema_version": PACK_SCHEMA_VERSION,
        "pack": "AUD-01 auditor export pack",
        "built_at": now.isoformat(),
        "query_window": {
            "from": from_utc.isoformat() if from_utc else None,
            "to": to_utc.isoformat() if to_utc else None,
            "receipt_hash": receipt_hash,
        },
        "counts": {
            "receipts": len(envelopes),
            "keys": n_keys,
            "timestamp_tokens": token_count,
            "policy_files": len(copied_policies),
        },
        "files": files,
    }
    (pack / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    zip_path = out_dir / ZIP_NAME
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(pack.rglob("*")):
            if p.is_file():
                # every entry lives under one top-level "audit-pack/" dir so
                # an unpacked zip is always exactly the pack directory
                zf.write(p, str(p.relative_to(out_dir)))

    return {
        "pack_dir": str(pack),
        "zip": str(zip_path),
        "window": manifest["query_window"],
        "counts": manifest["counts"],
        "manifest_files": len(files),
    }


def _verify_notes(receipts: int, timestamps: int, policies: str) -> str:
    return f"""# Offline verification notes

## Prerequisites

You need only Python 3.11+ with the `cryptography` package (`pip install
cryptography`). No network connection is used, wanted, or trusted at any
step. The verifier ships separately as `tools/verifier/verify_pack.py` in
the source repository; ask the operator to hand it to you alongside this
pack, or write your own — the manifest tells you everything it should check.

## Steps

1. If you received the `.zip`, unpack it once into a directory.
2. Run: `python verify_pack.py <unpacked pack directory>`
3. Read the verdict. Green means every manifest digest matched, every
   receipt signature validated against the embedded key snapshot within
   its validity window, and every claimed timestamp anchor carried its
   token. Red names the exact file or receipt that failed.
4. Exit code 0 is green; 1 is red. A "warning" (claim-sheet guard missing,
   for instance) does not change the exit code but is printed prominently.

## Expected contents

- `receipts.jsonl` — {receipts} receipt envelope(s), byte-exact.
- `keys/` — the trust-root snapshot (public keys only).
- `timestamps/` — {timestamps} RFC 3161 token(s) (see that directory's README when none).
- `policies/` — {policies}.
- `chain_graph.json` — reserved slot, pending P1.1a wire-up.
- `claims.md` — the plain-English claim sheet with its mandatory no-claim guard.

If any of the above is missing, the verifier will say so by name. It is
normal for this pack to contain no policy evidence and no timestamp tokens:
those absences are stated in the claim sheet rather than papered over.
"""


# ----------------------------------------------------------------- CLI -----


def _parse_utc(s: str) -> dt.datetime:
    d = dt.datetime.fromisoformat(s)
    return d.replace(tzinfo=dt.UTC) if d.tzinfo is None else d.astimezone(dt.UTC)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="AUD-01: build an offline auditor export pack (P1.7a)"
    )
    ap.add_argument("--evidence-store", required=True, help="evidence store JSONL (JSONL of {receipt_hash, jws})")
    ap.add_argument("--trust-roots", required=True, help="trust-root snapshot JSONL")
    ap.add_argument("--from", dest="from_s", help="window start, ISO-8601 (UTC assumed)")
    ap.add_argument("--to", dest="to_s", help="window end, ISO-8601 (UTC assumed)")
    ap.add_argument("--receipt-hash", help="optional single receipt (overrides window)")
    ap.add_argument("--policies-dir", help="optional policy directory (yaml/json) to include")
    ap.add_argument("--policy-receipts", help="optional JSONL of deployment-chain receipt ids")
    ap.add_argument("--out", required=True, help="output directory (pack + zip land inside)")
    ap.add_argument("--clock", help="pinned clock, ISO-8601 (deterministic builds)")
    args = ap.parse_args(argv)
    store_lines = pathlib.Path(args.policy_receipts).read_text().splitlines() if args.policy_receipts else None
    summary = build_pack(
        pathlib.Path(args.evidence_store),
        pathlib.Path(args.trust_roots),
        pathlib.Path(args.out),
        from_utc=_parse_utc(args.from_s) if args.from_s else None,
        to_utc=_parse_utc(args.to_s) if args.to_s else None,
        receipt_hash=args.receipt_hash,
        policies_dir=pathlib.Path(args.policies_dir) if args.policies_dir else None,
        policy_receipt_hashes=store_lines if store_lines is not None else None,
        clock=_parse_utc(args.clock) if args.clock else None,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
