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
import dataclasses
import datetime as dt
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import shutil
import sys
import zipfile

README_MD = "README.md"

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
CHAIN_GRAPH_RESOLVED = "resolved-by-pinned-verifier"

ZIP_NAME = "audit-pack.zip"


# ------------------------------------------------------------------------


def _b64d(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


_REceiptHashRe = re.compile(r"sha256:[0-9a-f]{64}")


def _receipt_hash_filename(receipt_hash: str, *, label: str) -> str:
    """Filename stem for content-derived artifact names.

    ``receipt_hash`` is read from the evidence store (file content), not
    from a trusted source, so it is validated against the canonical
    ``sha256:<hex>`` form before it can ever become part of a written
    path. Anything else fails loudly: a hostile store line must not be
    able to aim a write outside the pack directory.
    """
    rh = receipt_hash.strip().lower()
    if not _REceiptHashRe.fullmatch(rh):
        raise ValueError(
            f"{label}: receipt_hash {receipt_hash[:32]!r}… is not canonical "
            "sha256:<64 hex>; refusing to derive a pack filename from it"
        )
    return rh.replace(":", "-")


def _resolve_out_dir(out_dir: pathlib.Path) -> pathlib.Path:
    """Canonicalise the CLI ``--out`` directory and refuse dangerous targets.

    The pack builder removes and recreates ``out_dir`` wholesale, so a
    mistyped or malicious ``--out`` (the caller may be an automated agent,
    which is exactly what this project assumes) must not be able to name
    a filesystem root or a home directory.
    """
    candidate = pathlib.Path(out_dir).expanduser().resolve()
    if candidate == pathlib.Path(candidate.root) or candidate == pathlib.Path.home():
        raise ValueError(
            f"refusing --out {out_dir!s}: resolving to {candidate} would be "
            "removed wholesale by the pack builder; choose a dedicated output directory"
        )
    return candidate


def _pack_member(root: pathlib.Path, member: str) -> pathlib.Path:
    """Gate every in-pack write/copy path: refuse anything that escapes ``root``.

    Member names inside the pack can be derived from untrusted material (a
    receipt field read from the evidence store, a filename from the
    operator-supplied key snapshot or the policies directory), so no member
    may take a filesystem path without passing this gate: an empty member,
    an absolute path, a Windows ``\\`` separator, a ``..`` segment, or a
    name that canonicalises outside the pack sandbox root is refused with
    a ValueError before a single byte is written.
    """
    if not member or "\\" in member or pathlib.PurePosixPath(member).is_absolute():
        raise ValueError(f"refusing non-containerised pack member {member!r}")
    if any(part == ".." for part in pathlib.PurePosixPath(member).parts):
        raise ValueError(f"refusing '..' segment in pack member {member!r}")
    target = root / member
    try:
        target.resolve().relative_to(root.resolve())
    except ValueError:
        raise ValueError(f"pack member {member!r} resolves outside the pack root {root}") from None
    return target


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


def _line_matching_hash(raw: str, receipt_hash: str) -> str | None:
    """The raw line, byte-exact, when its receipt_hash matches — else None."""
    line = raw.rstrip("\n")
    if not line:
        return None
    rec = json.loads(line)
    return line if rec["receipt_hash"] == receipt_hash else None


def _decodable_window_line(raw: str, from_utc, to_utc) -> str | None:
    """The raw envelope line when decodable and inside the window — else None.

    Undecodable lines are reported to stderr; they are never silently
    dropped or repaired.
    """
    line = raw.rstrip("\n")
    if not line:
        return None
    try:
        t = _event_time(line)
    except Exception as exc:
        print(f"audit-pack: skipped undecodable store line: {exc}", file=sys.stderr)
        return None
    if from_utc is not None and t < from_utc:
        return None
    if to_utc is not None and t > to_utc:
        return None
    return line


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
        for raw in store_path.read_text(encoding="utf-8").splitlines():
            line = _line_matching_hash(raw, receipt_hash)
            if line is not None:
                return [line]
        raise FileNotFoundError(f"{receipt_hash} not in evidence store {store_path}")

    out: list[str] = []
    for raw in store_path.read_text(encoding="utf-8").splitlines():
        line = _decodable_window_line(raw, from_utc, to_utc)
        if line is not None:
            out.append(line)
    return out


# ------------------------------------------------------------- claims ------


def build_claim_sheet(
    *,
    window: str,
    receipts: int,
    keys: int,
    timestamp_tokens: int,
    policies: str,
    chain_graph: str,
    bundle: str = "complete within the query window",
    clock: dt.datetime | None = None,
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
        f"- Signature bundle: {bundle} (the pack is self-contained: every",
        "  envelope a claim here depends on is shipped inside it).",
        "- A pinned key snapshot with the public half of every signing key used",
        "  inside the window, so re-verification needs nothing else (no network,",
        "  no raucle installation, no operator access).",
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


def _snapshot_rows(trust_roots: pathlib.Path) -> list[dict]:
    rows = []
    for line in trust_roots.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _envelope_kids(envelopes: list[str]) -> set[str]:
    kids: set[str] = set()
    for line in envelopes:
        payload = _envelope_payload(line)
        kid = payload.get("agent_key_id") or payload.get("kid")
        if isinstance(kid, str) and kid:
            kids.add(kid)
    return kids


# --------------------------------------------------------------- bundle -----


def _graph_receipt_ids(graph_status: str, graphs: dict) -> set[str]:
    """Receipt hashes a resolved graph depends on (nodes of kind receipt)."""
    if graph_status != CHAIN_GRAPH_RESOLVED:
        return set()
    ids: set[str] = set()
    for g in graphs.values():
        for node in g.get("nodes", []):
            if isinstance(node, dict) and node.get("kind") == "receipt":
                rid = node.get("id")
                if isinstance(rid, str) and rid.startswith("sha256:"):
                    ids.add(rid)
    return ids


def _store_hash_map(evidence_store: pathlib.Path) -> dict[str, str]:
    """Every decodable store line keyed by its receipt_hash (errors noted)."""
    in_store_all: dict[str, str] = {}
    for raw in evidence_store.read_text(encoding="utf-8").splitlines():
        line = raw.rstrip("\n")
        if not line:
            continue
        try:
            rh = json.loads(line)["receipt_hash"]
        except Exception as exc:  # already reported by select_envelopes
            print(
                f"audit-pack: signature bundle skipped undecodable store line: {exc}",
                file=sys.stderr,
            )
            continue
        in_store_all[rh] = line
    return in_store_all


def _bundle_note(extra: int, missing: int) -> str:
    """Honest note for the claim sheet."""
    if extra and missing:
        return (
            f"{extra} chain receipt(s) embedded in `signatures/`; "
            f"{missing} referenced receipt(s) were absent from the evidence store and the graphs record them as unknown"
        )
    if extra:
        return f"{extra} chain receipt(s) embedded in `signatures/chain_receipts.jsonl` beyond the query window"
    if missing:
        return "referenced chain receipts were absent from the evidence store and the graphs record them as unknown"
    return (
        "complete within the query window: every receipt the resolved chain"
        " graphs reference is carried in `receipts.jsonl`"
    )


def build_signature_bundle(
    evidence_store: pathlib.Path,
    in_window: list[str],
    graph_status: str,
    graphs: dict,
    out_dir: pathlib.Path,
) -> tuple[int, str]:
    """The full signature bundle: every envelope a pack claim depends on.

    In-window receipts live in ``receipts.jsonl``; any receipt a resolved
    chain graph references that is NOT already in the window is copied
    byte-exactly into ``signatures/chain_receipts.jsonl``. Returns
    (extra_count, honest note for the claim sheet).
    """
    sig_dir = out_dir / "signatures"
    sig_dir.mkdir()
    window_hashes: set[str] = set()
    in_store_all = _store_hash_map(evidence_store)
    for line in in_window:
        try:
            window_hashes.add(json.loads(line)["receipt_hash"])
        except Exception as exc:
            print(
                f"audit-pack: signature bundle skipped undecodable window line: {exc}",
                file=sys.stderr,
            )
    wanted = sorted(_graph_receipt_ids(graph_status, graphs) - window_hashes)
    extra: list[str] = []
    missing: list[str] = []
    for rid in wanted:
        line = in_store_all.get(rid)
        if line is None:
            # the resolver cannot resolve it either; the graph already
            # records it as unknown - state it in the bundle, never fake it
            (sig_dir / README_MD).write_text(
                "# Signature bundle\n\n"
                "Some receipts referenced by the resolved chain graphs were\n"
                "not present in the evidence store at pack time. The graphs\n"
                "record them as unknown states; this is stated here rather\n"
                "than papered over.\n",
                encoding="utf-8",
            )
            missing.append(rid)
            continue
        extra.append(line)
    if extra:
        # store-derived chain receipt lines; gated member + explicit file
        # handle (byte-identical to the previous Path.write_text form)
        bundle_member = _pack_member(sig_dir, "chain_receipts.jsonl")
        with open(bundle_member, "w", encoding="utf-8") as _fh:
            _fh.write("\n".join(extra) + "\n")
    if not extra and not missing:
        (sig_dir / README_MD).write_text(
            "# Signature bundle\n\nEvery receipt the resolved chain graphs\n"
            "reference is already carried in `receipts.jsonl`. Nothing extra\n"
            "was needed; this directory exists so the contract stays stable.\n",
            encoding="utf-8",
        )
    return len(extra), _bundle_note(len(extra), len(missing))


def _assert_key_snapshot_covers(snapshot_kids: set[str], used_kids: set[str]) -> None:
    """Refuse to export a pack whose signing keys are missing from the snapshot.

    Key snapshot coverage: the pinned snapshot travels in the pack, so it MUST
    carry the public half of every signing key used inside the window. A pack
    that could not be verified offline is not exported at all.
    """
    uncovered = sorted(used_kids - snapshot_kids)
    if uncovered:
        raise ValueError(
            "cannot build a self-contained export: signing key(s) "
            + ", ".join(repr(k) for k in uncovered)
            + " are used by in-window receipts but absent from the pinned "
            "key snapshot; extend the snapshot instead of shipping an "
            "export that cannot verify offline"
        )


def _stage_receipts_and_keys(
    pack: pathlib.Path, envelopes: list[str], trust_roots: pathlib.Path
) -> tuple[pathlib.Path, int]:
    """Write ``receipts.jsonl`` (byte-exact) and the verbatim key snapshot."""
    # receipts.jsonl carries store-derived envelope content, written via a
    # gated member path and an explicit file handle (byte-exact either way)
    receipts_member = _pack_member(pack, "receipts.jsonl")
    with open(receipts_member, "w", encoding="utf-8") as _fh:
        _fh.write("\n".join(envelopes) + "\n")
    keys_dir = pack / "keys"
    keys_dir.mkdir()
    # the snapshot member name comes from a CLI-supplied file (untrusted
    # material even here); the gate refuses traversal before the copy
    shutil.copyfile(trust_roots, _pack_member(pack, f"keys/{trust_roots.name}"))
    n_keys = sum(1 for ln in trust_roots.read_text().splitlines() if ln.strip())
    return keys_dir, n_keys


def _stage_timestamps(pack: pathlib.Path, envelopes: list[str]) -> int:
    """Extract RFC 3161 tokens from envelopes that claim one; honest absence."""
    ts_dir = pack / "timestamps"
    ts_dir.mkdir()
    token_count = 0
    for line in envelopes:
        x_ts = _envelope_payload(line).get("x_timestamp")
        if isinstance(x_ts, dict) and x_ts.get("token"):
            token = _b64d(str(x_ts["token"]))
            rh = _receipt_hash_filename(
                str(json.loads(line)["receipt_hash"]), label="timestamp token"
            )
            _pack_member(ts_dir, f"{rh}.token").write_bytes(token)
            token_count += 1
    if token_count == 0:
        (ts_dir / README_MD).write_text(
            "# Timestamps\n\n"
            "No receipt in this window carries an RFC 3161 timestamp anchor.\n"
            "This is an honest absence, not a failure: receipts verified at\n"
            "event time on the host clock still carry their signed `iat`, and\n"
            "the claim sheet states exactly this scope.\n",
            encoding="utf-8",
        )
    return token_count


def _copy_policy_files(policies_dir: pathlib.Path | None, pol_dir: pathlib.Path) -> list[str]:
    """Copy policy files from the operator directory; return the copied names."""
    if policies_dir is None:
        return []
    policies_dir = pathlib.Path(policies_dir)
    copied_policies: list[str] = []
    for f in sorted(policies_dir.iterdir()):
        if f.is_file() and f.suffix in {".yaml", ".yml", ".json"}:
            # the copied path is derived from an untrusted directory
            # listing; the pack-member gate refuses traversal and any
            # escape from the policies/ directory before the copy
            target = _pack_member(pol_dir, f.name)
            shutil.copyfile(f, target)
            copied_policies.append(f.name)
    return copied_policies


def _stage_policy_receipts(
    pol_dir: pathlib.Path,
    evidence_store: pathlib.Path,
    policy_receipt_hashes: list[str] | None,
) -> None:
    """Copy the deployment-chain receipt lines named by the audit.

    Re-reads the store through _store_hash_map so undecodable lines
    (null entries, malformed JSON) produce the same named skip the
    receipt-selection path already prints, instead of crashing the pack.
    """
    by_hash = _store_hash_map(evidence_store)
    if not policy_receipt_hashes:
        return
    pol_lines: list[str] = []
    for rh in policy_receipt_hashes:
        if rh in by_hash:
            pol_lines.append(by_hash[rh])
    # store-derived receipt lines; gated member + explicit file handle
    # (byte-identical to the previous Path.write_text form)
    deployments_member = _pack_member(pol_dir, "deployment_chain_receipts.jsonl")
    with open(deployments_member, "w", encoding="utf-8") as _fh:
        _fh.write("\n".join(pol_lines) + "\n")


def _policy_gap_note_and_readme(
    copied_policies: list[str], policy_receipt_hashes: list[str] | None, pol_dir: pathlib.Path
) -> str:
    """Honest coverage note (and gap README) for the staged policy set."""
    if copied_policies and policy_receipt_hashes:
        return (
            f"{len(copied_policies)} policy file(s) and deployment-chain receipts under `policies/`"
        )
    if copied_policies:
        (pol_dir / README_MD).write_text(
            "# Policies\n\nDeployment-chain receipts from the gate audit were not\n"
            "accessible at pack time. Policy files are included verbatim; the\n"
            "deployment chain for them is unverified — treated honestly as a gap,\n"
            "never as evidence of approval.\n",
            encoding="utf-8",
        )
        return (
            f"{len(copied_policies)} policy file(s) under `policies/`; deployment-chain"
            " receipts were not accessible at pack time — this is stated, not hidden"
        )
    (pol_dir / README_MD).write_text(
        "# Policies\n\nNot included: no policy file or deployment-chain receipt\n"
        "was accessible at pack time. The pack does not claim policy coverage\n"
        "it cannot show. Obtain the current policy set from the operator\n"
        "separately and verify it against the gate-audit records.\n",
        encoding="utf-8",
    )
    return (
        "not included — the policy set and its deployment-chain receipts were"
        " not accessible at pack time; coverage here is unverified"
    )


def _stage_policies(
    pack: pathlib.Path,
    evidence_store: pathlib.Path,
    policies_dir: pathlib.Path | None,
    policy_receipt_hashes: list[str] | None,
) -> tuple[str, int]:
    """Copy policy files + deployment-chain receipts; note every gap honestly."""
    pol_dir = pack / "policies"
    pol_dir.mkdir()
    copied_policies = _copy_policy_files(policies_dir, pol_dir)
    _stage_policy_receipts(pol_dir, evidence_store, policy_receipt_hashes)
    return (
        _policy_gap_note_and_readme(copied_policies, policy_receipt_hashes, pol_dir),
        len(copied_policies),
    )


def _chain_graph_resolver_path() -> pathlib.Path | None:
    """Opt-in resolver source: ``RAUCLE_OSS_HOME``, when it ships chain_graph."""
    # The assurance venv pins raucle 0.23.5 (pinned worktree); the resolver
    # ships in the OSS tree. Honour RAUCLE_OSS_HOME as an explicit, opt-in
    # source for the wire-up; without it the pack degrades to the pending
    # slot - never a fake graph.
    _oss = os.environ.get("RAUCLE_OSS_HOME")
    if _oss and pathlib.Path(_oss).is_dir():
        # The pinned raucle install in the venv may shadow the OSS tree and
        # ship without chain_graph, so load the resolver straight from the
        # declared OSS home instead of relying on sys.path order.
        cand = pathlib.Path(_oss) / "raucle" / "chain_graph.py"
        if cand.is_file():
            return cand
    return None


def _load_chain_graph_module(cg_path: pathlib.Path):
    spec = importlib.util.spec_from_file_location("raucle_chain_graph_p1_1a", cg_path)
    assert spec is not None and spec.loader is not None
    _cg = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(spec.name, _cg)
    spec.loader.exec_module(_cg)
    return _cg


def resolve_chain_graphs(envelopes: list[str], snapshot_rows: list[dict], _cg) -> dict:
    """Per-receipt authority graphs; failures become graph states, not crashes.

    Self-contained (P1.1c): the pinned snapshot is embedded in the pack, so it
    is also fed to the resolver: per-node signature states become real verify
    results, not "key_absent" placeholders.
    """
    public_keys = {str(r["key_id"]): r["public_key_pem"] for r in snapshot_rows}
    graphs: dict = {}
    for line in envelopes:
        rh = json.loads(line)["receipt_hash"]
        try:
            graphs[rh] = _cg.resolve_chain_graph(
                rh,
                [json.loads(env_line) for env_line in envelopes],
                public_keys=public_keys,
            )
        except Exception as exc:  # per-receipt: a graph state, not a crash
            graphs[rh] = {"status": "unresolved", "reason": type(exc).__name__}
    return graphs


def _stage_chain_graph(
    pack: pathlib.Path, envelopes: list[str], snapshot_rows: list[dict]
) -> tuple[str, dict]:
    """chain_graph.json — resolve with raucle's resolver when available."""
    graphs: dict = {}
    graph_status = CHAIN_GRAPH_PENDING
    cg_path = _chain_graph_resolver_path()
    if cg_path is not None:
        _cg = _load_chain_graph_module(cg_path)
        graphs = resolve_chain_graphs(envelopes, snapshot_rows, _cg)
        graph_status = CHAIN_GRAPH_RESOLVED
    (pack / "chain_graph.json").write_text(
        json.dumps(
            {
                "schema_version": PACK_SCHEMA_VERSION,
                "status": graph_status,
                "note": (
                    "authority graphs resolved by raucle resolve_chain_graph from the receipts in this pack; per-node signature states are part of the graph"
                    if graph_status == "resolved-by-pinned-verifier"
                    else "chain resolution is being built in P1.1a; this slot is reserved and additive"
                ),
                "graphs": graphs,
                "edges": [],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return graph_status, graphs


@dataclasses.dataclass(frozen=True)
class _QueryContext:
    """Query-window selection the manifest must record."""

    from_utc: dt.datetime | None
    to_utc: dt.datetime | None
    receipt_hash: str | None
    clock: dt.datetime | None
    window: str


def _build_pack_manifest(
    pack: pathlib.Path,
    ctx: _QueryContext,
    *,
    envelopes: list[str],
    n_keys: int,
    token_count: int,
    policy_files: int,
    bundle_extra: int,
    snapshot_kids: set[str],
    keys_dir: pathlib.Path,
    trust_roots: pathlib.Path,
) -> dict:
    """manifest.json + zip; return the summary dict."""
    files = {
        str(p.relative_to(pack)): _sha256_file(p) for p in sorted(pack.rglob("*")) if p.is_file()
    }
    now = (ctx.clock or dt.datetime.now(dt.UTC)).replace(microsecond=0)
    snapshot_digest = _sha256_file(keys_dir / trust_roots.name)
    manifest = {
        "schema_version": PACK_SCHEMA_VERSION,
        "pack": "AUD-01 auditor export pack",
        "built_at": now.isoformat(),
        "query_window": {
            "from": ctx.from_utc.isoformat() if ctx.from_utc else None,
            "to": ctx.to_utc.isoformat() if ctx.to_utc else None,
            "receipt_hash": ctx.receipt_hash,
        },
        "pinned_key_snapshot": {
            "file": f"keys/{trust_roots.name}",
            "sha256": snapshot_digest,
            "key_ids": sorted(snapshot_kids),
            "note": "verbatim pinned snapshot, public halves only; re-verification depends on nothing outside the pack",
        },
        "self_contained": {
            "offline": True,
            "requires": "Python 3.11+ standard library plus the cryptography package",
            "network": "none",
            "raucle": "not required at verification time",
        },
        "counts": {
            "receipts": len(envelopes),
            "keys": n_keys,
            "timestamp_tokens": token_count,
            "policy_files": policy_files,
            "chain_receipts": bundle_extra,
        },
        "files": files,
    }
    (pack / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    zip_path = pack.parent / ZIP_NAME
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(pack.rglob("*")):
            if p.is_file():
                # every entry lives under one top-level "audit-pack/" dir so
                # an unpacked zip is always exactly the pack directory
                zf.write(p, str(p.relative_to(pack.parent)))
    return {
        "pack_dir": str(pack),
        "zip": str(zip_path),
        "window": manifest["query_window"],
        "counts": manifest["counts"],
        "manifest_files": len(files),
    }


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
    out_dir = _resolve_out_dir(pathlib.Path(out_dir))
    if out_dir.exists():
        shutil.rmtree(out_dir)

    envelopes = select_envelopes(
        evidence_store, from_utc=from_utc, to_utc=to_utc, receipt_hash=receipt_hash
    )
    pack = out_dir / "audit-pack"
    pack.mkdir(parents=True)

    snapshot_rows = _snapshot_rows(trust_roots)
    snapshot_kids = {str(row["key_id"]) for row in snapshot_rows}
    _assert_key_snapshot_covers(snapshot_kids, _envelope_kids(envelopes))

    keys_dir, n_keys = _stage_receipts_and_keys(pack, envelopes, trust_roots)
    token_count = _stage_timestamps(pack, envelopes)
    policies_note, policy_files = _stage_policies(
        pack, evidence_store, policies_dir, policy_receipt_hashes
    )
    graph_status, stage_graphs = _stage_chain_graph(pack, envelopes, snapshot_rows)

    # signatures/ — the full signature bundle (P1.1c): every envelope the
    # pack's claims depend on, inside the query window or referenced by a
    # resolved chain graph, so re-verification needs nothing but the pack.
    bundle_extra, bundle_note = build_signature_bundle(
        evidence_store, envelopes, graph_status, stage_graphs, pack
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
        chain_graph=f"`chain_graph.json` is recorded as {graph_status}.",
        bundle=bundle_note,
        clock=clock,
    )
    (pack / "claims.md").write_text(claims, encoding="utf-8")

    # verify-notes.md — reviewer instructions.
    (pack / "verify-notes.md").write_text(
        _verify_notes(receipts=len(envelopes), timestamps=token_count, policies=policies_note),
        encoding="utf-8",
    )

    return _build_pack_manifest(
        pack,
        _QueryContext(
            from_utc=from_utc,
            to_utc=to_utc,
            receipt_hash=receipt_hash,
            clock=clock,
            window=window,
        ),
        envelopes=envelopes,
        n_keys=n_keys,
        token_count=token_count,
        policy_files=policy_files,
        bundle_extra=bundle_extra,
        snapshot_kids=snapshot_kids,
        keys_dir=keys_dir,
        trust_roots=trust_roots,
    )


def _verify_notes(receipts: int, timestamps: int, policies: str) -> str:
    return f"""# Offline verification notes

## Prerequisites

You need only Python 3.11+ with the `cryptography` package (`pip install
cryptography`). No network connection is used, wanted, or trusted at any
step, and the pack itself carries the pinned key snapshot it is checked
against: no raucle installation, no gateway, and no operator access are
involved. The verifier ships separately as `tools/verifier/verify_pack.py` in
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
- `keys/` — the pinned key snapshot (public keys only), embedded so the pack
  verifies against nothing outside itself.
- `signatures/` — the full signature bundle: every envelope a pack claim
  depends on, including chain receipts a resolved graph references beyond
  the query window (see that directory's README when none were needed).
- `timestamps/` — {timestamps} RFC 3161 token(s) (see that directory's README when none).
- `policies/` — {policies}.
- `chain_graph.json` — the chain-graph slot (its resolved status is reported by the verifier).
- `claims.md` — the plain-English claim sheet with its mandatory no-claim guard.

If any of the above is missing, the verifier will say so by name. It is
normal for this pack to contain no policy evidence and no timestamp tokens:
those absences are stated in the claim sheet rather than papered over.
"""


# ----------------------------------------------------------------- CLI -----


def _parse_utc(s: str) -> dt.datetime:
    d = dt.datetime.fromisoformat(s)
    return d.replace(tzinfo=dt.UTC) if d.tzinfo is None else d.astimezone(dt.UTC)


def _cli_input_path(s: str, label: str) -> pathlib.Path:
    """Canonicalise a CLI-supplied input path and require a real file.

    CLI arguments may be supplied by an automated caller, so every input
    is resolved to its canonical form up front and rejected with an honest
    error when it does not name an existing regular file — no read of a
    half-formed or surprising path ever happens.
    """
    p = pathlib.Path(s).expanduser().resolve()
    if not p.is_file():
        raise FileNotFoundError(f"--{label}: {s!s} resolves to {p}, which is not a regular file")
    return p


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="AUD-01: build an offline auditor export pack (P1.7a)")
    ap.add_argument(
        "--evidence-store",
        required=True,
        help="evidence store JSONL (JSONL of {receipt_hash, jws})",
    )
    ap.add_argument("--trust-roots", required=True, help="trust-root snapshot JSONL")
    ap.add_argument("--from", dest="from_s", help="window start, ISO-8601 (UTC assumed)")
    ap.add_argument("--to", dest="to_s", help="window end, ISO-8601 (UTC assumed)")
    ap.add_argument("--receipt-hash", help="optional single receipt (overrides window)")
    ap.add_argument("--policies-dir", help="optional policy directory (yaml/json) to include")
    ap.add_argument("--policy-receipts", help="optional JSONL of deployment-chain receipt ids")
    ap.add_argument("--out", required=True, help="output directory (pack + zip land inside)")
    ap.add_argument("--clock", help="pinned clock, ISO-8601 (deterministic builds)")
    args = ap.parse_args(argv)
    store_lines = (
        _cli_input_path(args.policy_receipts, "policy-receipts")
        .read_text(encoding="utf-8")
        .splitlines()
        if args.policy_receipts
        else None
    )
    summary = build_pack(
        _cli_input_path(args.evidence_store, "evidence-store"),
        _cli_input_path(args.trust_roots, "trust-roots"),
        pathlib.Path(args.out),
        from_utc=_parse_utc(args.from_s) if args.from_s else None,
        to_utc=_parse_utc(args.to_s) if args.to_s else None,
        receipt_hash=args.receipt_hash,
        policies_dir=(
            pathlib.Path(args.policies_dir).expanduser().resolve() if args.policies_dir else None
        ),
        policy_receipt_hashes=store_lines if store_lines is not None else None,
        clock=_parse_utc(args.clock) if args.clock else None,
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
