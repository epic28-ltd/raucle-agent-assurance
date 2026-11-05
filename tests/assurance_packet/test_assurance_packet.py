# SPDX-License-Identifier: Apache-2.0
"""OV-1 Agent Assurance Packet tests.

Determinism (golden sha256 across runs), fail-visible tamper/missing
input handling, bounded disclosure (no receipt reasons anywhere) and the
textContent-only HTML contract pinned by test.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import pathlib
import subprocess
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO_STORE = REPO_ROOT / "services" / "investigation-ui" / "demo_data" / "evidence_store.jsonl"
SCRIPT = REPO_ROOT / "scripts" / "rauckle-assurance-packet"

_spec = importlib.util.spec_from_file_location(
    "oaa_assurance_packet", REPO_ROOT / "services" / "assurance_packet" / "packet.py"
)
assert _spec is not None
assert _spec.loader is not None
ap_mod = importlib.util.module_from_spec(_spec)
sys.modules["oaa_assurance_packet"] = ap_mod
_spec.loader.exec_module(ap_mod)


# ---------------------------------------------------------------- helpers ---


@pytest.fixture(scope="module")
def built(tmp_path_factory: pytest.TempPathFactory) -> tuple[pathlib.Path, bytes, dict]:
    out = tmp_path_factory.mktemp("ap-run1")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--evidence-store", str(DEMO_STORE), "--out-dir", str(out)],
        capture_output=True,
        text=True,
        check=True,
    )
    json_path = out / "agent_assurance_packet.json"
    raw = json_path.read_bytes()
    return json_path, raw, json.loads(proc.stdout)


# ------------------------------------------------------------- determinism ---


def test_deterministic_bytes_and_sha_across_runs(built) -> None:
    _, raw, summary = built
    out2 = built[0].parent.parent / "ap-run2"
    subprocess.run(
        [sys.executable, str(SCRIPT), "--evidence-store", str(DEMO_STORE), "--out-dir", str(out2)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert (out2 / "agent_assurance_packet.json").read_bytes() == raw
    expected = json.loads(raw)["packet_content_sha256"]
    assert expected == summary["packet_content_sha256"]
    assert expected.startswith("sha256:")
    # the packet body re-derives its own stamped digest
    body = json.loads(raw)
    stamped = body.pop("packet_content_sha256")
    canon = ap_mod.canonical_json(body)

    assert stamped == "sha256:" + hashlib.sha256(canon.encode()).hexdigest()


def test_packet_carries_guard_and_schema_version(built) -> None:
    packet = json.loads(built[1])
    assert packet["schema_version"] == 1
    assert packet["kind"] == "agent_assurance_packet"
    assert packet["guard"] == ap_mod.GUARD_SENTENCE
    coverage = packet["gate_coverage"]
    total = (
        coverage["admitted"]
        + coverage["refused"]
        + coverage["held"]
        + coverage["other"]
        + coverage["without_gate"]
    )
    assert packet["receipt_chain"]["line_count"] == 2
    assert total == 2


def test_governance_slots_tolerate_empty_and_accept_ids() -> None:
    packet = ap_mod.build_packet(DEMO_STORE)
    assert set(packet["governance_mapping"]) >= {
        "dora",
        "eu_ai_act",
        "iso_42001",
        "soc_2",
        "nist_ai_rmf",
        "owasp_llm",
    }
    assert all(v == [] for v in packet["governance_mapping"].values())
    packet2 = ap_mod.build_packet(
        DEMO_STORE,
        governance_mapping={"dora": ["II-6.3"], "nist_ai_rmf": ["MAP-2-a"]},
        capability_refs=["cap:fs.write@1"],
        policy_proof_refs=["pp:policy-bundle-a"],
        risk_annotations=["RA-1: outbound egress restricted to allowlist"],
    )
    assert packet2["governance_mapping"]["dora"] == ["II-6.3"]
    assert packet2["governance_mapping"]["owasp_llm"] == []
    assert packet2["capability_refs"] == ["cap:fs.write@1"]
    assert packet2["risk_annotations"][0].startswith("RA-1")


# ------------------------------------------------------------ fail-visible ---


def test_tampered_receipt_hash_fails_with_named_error(tmp_path: pathlib.Path) -> None:
    store = tmp_path / "store.jsonl"
    line = json.loads(DEMO_STORE.read_text().splitlines()[0])
    # flip one character inside the JWS: recorded hash no longer re-derives
    jws = list(line["jws"])
    jws[40] = "A" if jws[40] != "A" else "B"
    line["jws"] = "".join(jws)
    store.write_text(json.dumps(line) + "\n")
    with pytest.raises(ValueError, match="tampered"):
        ap_mod.build_packet(store)


def test_tampered_payload_fails(tmp_path: pathlib.Path) -> None:
    # a payload edited after the fact keeps its recorded hash, so the
    # JWS must re-derive: editing the payload changes the JWS bytes
    store = tmp_path / "store.jsonl"
    line = json.loads(DEMO_STORE.read_text().splitlines()[1])
    parts = line["jws"].split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    payload["guardrail_verdict"] = "allow"
    parts[1] = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    line["jws"] = ".".join(parts)
    store.write_text(json.dumps(line) + "\n")
    with pytest.raises(ValueError, match="tampered"):
        ap_mod.build_packet(store)


def test_missing_store_is_named_error(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ValueError, match="evidence store not found"):
        ap_mod.build_packet(tmp_path / "absent.jsonl")


def test_cli_fails_nonzero_on_tamper(tmp_path: pathlib.Path) -> None:
    store = tmp_path / "store.jsonl"
    line = json.loads(DEMO_STORE.read_text().splitlines()[0])
    line["receipt_hash"] = "sha256:" + "0" * 64
    store.write_text(json.dumps(line) + "\n")
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--evidence-store",
            str(store),
            "--out-dir",
            str(tmp_path / "o"),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "tampered" in (result.stderr + result.stdout)


# ------------------------------------------------------ bounded disclosure ---


def test_no_receipt_reasons_enter_packet_or_html(built) -> None:
    _, raw, _ = built
    packet = json.loads(raw)
    needle = "/etc/passwd"
    assert needle not in raw.decode()
    assert needle not in ap_mod.html_summary(packet)


# ---------------------------------------------------------- html contract ---


def test_html_summary_is_textcontent_only(built) -> None:
    packet = json.loads(built[1])
    html = ap_mod.html_summary(packet)
    lower = html.lower()
    assert "<script" not in lower
    assert "javascript:" not in lower
    assert "onload=" not in lower
    assert "onclick=" not in lower
    assert "innerHTML" not in html
    assert "document.write" not in html
    assert ap_mod.GUARD_SENTENCE in html
    assert html.startswith("<!doctype html>")
    assert html.endswith("</html>\n")


def test_html_summary_writes_from_cli(built, tmp_path: pathlib.Path) -> None:
    out = built[0].parent
    html = (out / "agent_assurance_packet.html").read_text()
    packet = json.loads(built[1])
    assert ap_mod.GUARD_SENTENCE in html
    assert str(packet["receipt_chain"]["line_count"]) in html
