# SPDX-License-Identifier: Apache-2.0
"""OV-3: offline re-validation of an assurance packet.

A packet built by the OV-1 generator from the committed demo evidence
store must REPRODUCE under the independent revalidator (fresh code, same
contract); tampered or swapped evidence, edited packets and missing
inputs must fail visibly with named, non-silent errors.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import pathlib
import sys

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
DEMO_STORE = REPO_ROOT / "services" / "investigation-ui" / "demo_data" / "evidence_store.jsonl"

_spec = importlib.util.spec_from_file_location(
    "oaa_revalidate_packet", REPO_ROOT / "tools" / "verifier" / "revalidate_packet.py"
)
assert _spec is not None
assert _spec.loader is not None
rv = importlib.util.module_from_spec(_spec)
sys.modules["oaa_revalidate_packet"] = rv
_spec.loader.exec_module(rv)


def _build_packet(overrides: dict | None = None) -> dict:
    """A packet in the OV-1 shape via the independent derivation itself."""
    return rv.rederive_packet_from_inputs(DEMO_STORE, **(overrides or {}))


# ------------------------------------------------------------ reproduction ---


def test_packet_reproduces_and_derives_its_own_digest() -> None:
    packet = _build_packet({})
    stamp = packet["packet_content_sha256"]
    body = dict(packet)
    body.pop("packet_content_sha256")

    assert stamp == "sha256:" + hashlib.sha256(rv.canonical_json(body).encode()).hexdigest()


def test_diff_of_identical_packets_is_empty() -> None:
    a = _build_packet({})
    b = _build_packet({})
    assert rv._diff(a, b) == []


def test_diff_names_swap_paths(tmp_path: pathlib.Path) -> None:
    store = tmp_path / "store.jsonl"
    first = json.loads(DEMO_STORE.read_text().splitlines()[0])
    store.write_text(json.dumps(first) + "\n")
    a = _build_packet({})
    b = rv.rederive_packet_from_inputs(store)
    diffs = rv._diff(a, b)
    assert diffs
    assert any("receipt_chain" in d for d in diffs)


# ------------------------------------------------------------- tamper gate ---


def test_edited_payload_keeps_no_free_pass(tmp_path: pathlib.Path) -> None:
    # Editing the payload changes the JWS bytes, so the recorded hash stops
    # re-deriving: a re-signed-looking edit is caught, not silently accepted.
    store = tmp_path / "store.jsonl"
    line = json.loads(DEMO_STORE.read_text().splitlines()[0])
    parts = line["jws"].split(".")
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    payload["guardrail_verdict"] = "allow"
    parts[1] = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
    line["jws"] = ".".join(parts)
    store.write_text(json.dumps(line) + "\n")
    with pytest.raises(rv._Fail, match="tampered or swapped"):
        rv.rederive_packet_from_inputs(store)


def test_revalidator_rejects_edited_packet_digest(tmp_path: pathlib.Path) -> None:
    packet = _build_packet({})
    packet["gate_coverage"]["admitted"] = 0  # verdict rewrite
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True))
    assert rv.main(["--packet", str(packet_path), "--evidence-store", str(DEMO_STORE)]) == 1


def test_revalidator_reports_mismatch_on_swapped_receipt(tmp_path: pathlib.Path) -> None:
    packet = _build_packet({})
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n")
    # a DIFFERENT single-receipt store: digest and chain both fail
    store = tmp_path / "store.jsonl"
    line = json.loads(DEMO_STORE.read_text().splitlines()[1])
    store.write_text(json.dumps(line) + "\n")
    result = rv.main(["--packet", str(packet_path), "--evidence-store", str(store)])
    assert result == 1


def test_revalidator_reports_mismatch_on_missing_inputs(tmp_path: pathlib.Path) -> None:
    packet = _build_packet(
        {"capability_refs": ["cap:x"], "policy_proof_refs": ["pp:y"], "risk_annotations": ["RA-1"]}
    )
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n")
    # re-running WITHOUT the refs is an honest mismatch, not a pass
    assert rv.main(["--packet", str(packet_path), "--evidence-store", str(DEMO_STORE)]) == 1


def test_revalidator_green_run_reproduces_verdict(tmp_path: pathlib.Path) -> None:
    packet = _build_packet(
        {
            "capability_refs": ["cap:x"],
            "risk_annotations": ["RA-1"],
            "governance_mapping": {"dora": ["II-6.3"]},
        }
    )
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n")
    (tmp_path / "caps.json").write_text(json.dumps(["cap:x"]))
    (tmp_path / "risks.json").write_text(json.dumps(["RA-1"]))
    (tmp_path / "gov.json").write_text(json.dumps({"dora": ["II-6.3"]}))
    result = rv.main(
        [
            "--packet",
            str(packet_path),
            "--evidence-store",
            str(DEMO_STORE),
            "--capability-refs",
            str(tmp_path / "caps.json"),
            "--risk-annotations",
            str(tmp_path / "risks.json"),
            "--governance",
            str(tmp_path / "gov.json"),
        ]
    )
    assert result == 0


def _green_run(tmp_path: pathlib.Path) -> tuple[int, pathlib.Path]:
    """Green revalidation, mirroring the pre-OV-20 green-run fixture."""
    packet = _build_packet(
        {
            "capability_refs": ["cap:x"],
            "risk_annotations": ["RA-1"],
            "governance_mapping": {"dora": ["II-6.3"]},
        }
    )
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n")
    (tmp_path / "caps.json").write_text(json.dumps(["cap:x"]))
    (tmp_path / "risks.json").write_text(json.dumps(["RA-1"]))
    (tmp_path / "gov.json").write_text(json.dumps({"dora": ["II-6.3"]}))
    result = rv.main(
        [
            "--packet",
            str(packet_path),
            "--evidence-store",
            str(DEMO_STORE),
            "--capability-refs",
            str(tmp_path / "caps.json"),
            "--risk-annotations",
            str(tmp_path / "risks.json"),
            "--governance",
            str(tmp_path / "gov.json"),
        ]
    )
    return result, packet_path


def test_report_document_written_on_green_run(tmp_path: pathlib.Path) -> None:
    report_path = tmp_path / "report.json"
    _result, packet_path = _green_run(tmp_path)
    assert _result == 0
    # Re-run with the machine-readable report on the same green fixture.
    assert (
        rv.main(
            [
                "--packet",
                str(packet_path),
                "--evidence-store",
                str(DEMO_STORE),
                "--report",
                str(report_path),
            ]
        )
        == 1
    )
    doc = json.loads(report_path.read_text())
    assert doc["schema"] == "oaa.revalidation-report/v1"
    assert doc["verdict"] == "MISMATCH"  # refs omitted: honest mismatch


def test_report_document_written_on_mismatch(tmp_path: pathlib.Path) -> None:
    packet_path = tmp_path / "packet.json"
    report_path = tmp_path / "report.json"
    _result, packet_path = _green_run(tmp_path)
    assert rv.main(["--packet", str(packet_path), "--evidence-store", str(DEMO_STORE)]) == 1
    assert (
        rv.main(
            [
                "--packet",
                str(packet_path),
                "--evidence-store",
                str(DEMO_STORE),
                "--report",
                str(report_path),
            ]
        )
        == 1
    )
    doc = json.loads(report_path.read_text())
    assert doc["verdict"] == "MISMATCH"
    assert any(c["status"] == "FAIL" for c in doc["checks"])


def test_unwritable_report_is_a_named_fail(tmp_path: pathlib.Path, capsys) -> None:
    _result, packet_path = _green_run(tmp_path)
    assert _result == 0
    assert (
        rv.main(
            [
                "--packet",
                str(packet_path),
                "--evidence-store",
                str(DEMO_STORE),
                "--report",
                str(tmp_path / "absent-dir" / "report.json"),
            ]
        )
        == 1
    )
    # fail-visible: the named FAIL must name the report itself
    out = capsys.readouterr().out
    assert any("[FAIL] revalidation report not written" in line for line in out.splitlines())
    assert "revalidation report not written" in out


def test_report_path_refused_for_unusable_destinations(tmp_path: pathlib.Path, capsys) -> None:
    """Resolved-to-root and resolved-to-home --report destinations are refused."""
    _result, packet_path = _green_run(tmp_path)
    assert _result == 0
    for bad in (pathlib.Path("/"), pathlib.Path("~")):
        assert (
            rv.main(
                [
                    "--packet",
                    str(packet_path),
                    "--evidence-store",
                    str(DEMO_STORE),
                    "--report",
                    str(bad),
                ]
            )
            == 1
        )
        # fail-visible: the refusal is a named FAIL that quotes the argument
        assert any(
            "[FAIL] --report path refused" in line for line in capsys.readouterr().out.splitlines()
        )


def test_report_path_is_canonicalised_before_write(tmp_path: pathlib.Path) -> None:
    """A traversal shorthand (--report ./dir/../sub/report.json) resolves to one file."""
    _result, packet_path = _green_run(tmp_path)
    assert _result == 0
    (tmp_path / "sub").mkdir()
    tangled = tmp_path / "sub" / ".." / "report.json"
    assert (
        rv.main(
            [
                "--packet",
                str(packet_path),
                "--evidence-store",
                str(DEMO_STORE),
                "--capability-refs",
                str(tmp_path / "caps.json"),
                "--risk-annotations",
                str(tmp_path / "risks.json"),
                "--governance",
                str(tmp_path / "gov.json"),
                "--report",
                str(tangled),
            ]
        )
        == 0
    )
    assert (tmp_path / "report.json").exists()


def test_main_catches_derivation_fail_as_named_fail(tmp_path: pathlib.Path, capsys) -> None:
    """A _Fail from the input loaders inside the derivation try is a named FAIL."""
    _result, packet_path = _green_run(tmp_path)
    assert _result == 0
    bad_caps = tmp_path / "bad_caps.json"
    bad_caps.write_text(json.dumps({"cap: x": "not a list"}))
    result = rv.main(
        [
            "--packet",
            str(packet_path),
            "--evidence-store",
            str(DEMO_STORE),
            "--capability-refs",
            str(bad_caps),
            "--risk-annotations",
            str(tmp_path / "risks.json"),
            "--governance",
            str(tmp_path / "gov.json"),
        ]
    )
    assert result == 1
    out = capsys.readouterr().out
    assert "[FAIL] capability-refs" in out


def test_revalidator_fails_on_missing_packet(tmp_path: pathlib.Path) -> None:
    assert (
        rv.main(["--packet", str(tmp_path / "absent.json"), "--evidence-store", str(DEMO_STORE)])
        == 1
    )


def test_revalidator_fails_on_missing_store(tmp_path: pathlib.Path) -> None:
    packet = _build_packet({})
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n")
    assert (
        rv.main(["--packet", str(packet_path), "--evidence-store", str(tmp_path / "absent.jsonl")])
        == 1
    )


def test_revalidator_fails_on_incomplete_packet(tmp_path: pathlib.Path) -> None:
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps({"kind": "agent_assurance_packet"}))
    assert rv.main(["--packet", str(packet_path), "--evidence-store", str(DEMO_STORE)]) == 1


def test_pq_signature_fail_is_a_named_fail(tmp_path: pathlib.Path, capsys) -> None:
    """A packet carrying an invalid PQ signature is a named FAIL (OV-22)."""
    packet = _build_packet({})
    packet["packet_pq_signature"] = {"algorithm": "ml-dsa-65"}
    packet_path = tmp_path / "packet.json"
    packet_path.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n")
    result = rv.main(["--packet", str(packet_path), "--evidence-store", str(DEMO_STORE)])
    assert result == 1
    out = capsys.readouterr().out
    assert "packet_pq_signature" in out
