# SPDX-License-Identifier: Apache-2.0
"""R1 coverage endpoint tests (GET /coverage/{org}, offline, demo fixtures).

The numbers below are asserted EXACTLY against the committed demo fixture
corpus through the app's real data plane: the endpoint rebuilds the same
receipt/trace index rows DemoData correlated and passes them to the COR-01
engine's ``coverage`` metric at ``at=None`` (as if every window had closed —
no wall clock anywhere). The expected values were derived from the corpus's
documented per-trace correlation states (runs.json + the receipt indexes),
not from the code under test.
"""

from __future__ import annotations

import json
import pathlib
import shutil
import sys

import pytest
from fastapi.testclient import TestClient

UI = pathlib.Path(__file__).resolve().parents[1]

sys.path.insert(0, str(UI / "src"))
for _src in (
    UI.parents[1] / "packages" / "raucle-adapter" / "src",
    UI.parents[1] / "services" / "correlation" / "src",
    UI.parents[1] / "services" / "rules" / "src",
):
    sys.path.insert(0, str(_src))

from oaa_investigation_ui.app import _coverage_org, create_app  # noqa: E402

DATA_DIR = UI / "demo_data"


@pytest.fixture(scope="module")
def data_dir(tmp_path_factory: pytest.TempPathFactory) -> pathlib.Path:
    d = tmp_path_factory.mktemp("coverage-data")
    shutil.copytree(DATA_DIR, d, dirs_exist_ok=True)
    return d


@pytest.fixture(scope="module")
def client(data_dir: pathlib.Path) -> TestClient:
    return TestClient(create_app(data_dir))


def test_endpoint_returns_exact_fixture_numbers(client: TestClient) -> None:
    """Exact numbers over the committed corpus (14 observed actions).

    11 of 14 observed agent actions carry a correlated receipt (7 matched,
    1 duplicate, 1 late_arrival, 2 rows of one ambiguous trace); 3 observed
    actions reconciled past grace with no receipt (the SEC-001 suppressed
    demo, the t-w03-bypass SEC-001 demo, and the spanref trace whose receipt
    points at a trace id with no observed record). The spanref receipt-side
    ``trace_missing`` state never appears here: it names an eventless trace
    id, so it cannot credit or debit the action plane.
    """
    r = client.get("/coverage/demo")
    assert r.status_code == 200
    body = r.json()
    assert body["org"] == "demo"
    assert body["schema_version"] == "oaa.coverage/v1"
    assert body["metric"] == "receipted_share"
    assert isinstance(body["basis"], str)
    assert body["breakdown"] == {
        "total": 14,
        "receipted": 11,
        "out_of_gate": 3,
        "pending": 0,
    }
    assert body["receipted_share"] == round(11 / 14, 4)  # 0.7857
    assert body["states"] == {
        "ambiguous": 2,
        "duplicate": 1,
        "late_arrival": 1,
        "matched": 7,
        "receipt_missing": 3,
    }
    assert body["by_tool"]["shell"] == {
        "total": 6,
        "receipted": 4,
        "out_of_gate": 2,
        "pending": 0,
        "receipted_share": 0.6667,
    }
    assert body["by_tool"]["file_write"]["total"] == 6
    assert body["by_tool"]["file_write"]["receipted"] == 5
    assert body["by_tool"]["file_write"]["out_of_gate"] == 1
    # per-tool rollup still partitions the headline plane (coherence)
    assert sum(r["total"] for r in body["by_tool"].values()) == body["breakdown"]["total"]
    assert sum(r["receipted"] for r in body["by_tool"].values()) == body["breakdown"]["receipted"]
    # agents from the committed runs.json attribution
    assert body["by_agent"]["oaa-sim"]["total"] == 13
    assert body["by_agent"]["oaa-sim"]["receipted_share"] == 0.7692
    assert body["by_agent"]["oaa-spike"]["total"] == 1
    assert body["by_agent"]["oaa-spike"]["receipted_share"] == 1.0


def test_flags_exact_from_fixture(client: TestClient) -> None:
    r = client.get("/coverage/demo")
    assert r.status_code == 200
    flags = r.json()["flags"]
    # The demo corpus carries receipt-missing past grace on exactly three
    # observed actions (both are shell/file_write actions of oaa-sim); both
    # oaa-sim and oaa-spike minted receipts, so no shadow agents; every
    # tool saw at least one receipted action somewhere, so no
    # uninstrumented tools.
    assert flags["count"] == {
        "bypass_candidates": 3,
        "shadow_agents": 0,
        "uninstrumented_tools": 0,
    }
    assert sorted(c["trace_id"] for c in flags["bypass_candidates"]) == [
        "t-sim-sup-0000000000000000000000000000aa",
        "t-w03-bypass-b2",
        "t-w03-spanref-e5",
    ]
    for cand in flags["bypass_candidates"]:
        assert cand["agent"] == "oaa-sim"
        assert cand["state"] == "receipt_missing"
        assert cand["evidence_class"] == "trace_plane_only"
    assert flags["shadow_agents"] == []
    assert flags["uninstrumented_tools"] == []


def test_coverage_is_deterministic_byte_identical(client: TestClient) -> None:
    one = client.get("/coverage/demo")
    two = client.get("/coverage/demo")
    assert one.status_code == two.status_code == 200
    assert json.dumps(one.json(), sort_keys=True) == json.dumps(two.json(), sort_keys=True)


def test_unknown_org_is_404_unavailable_not_zero(client: TestClient) -> None:
    r = client.get("/coverage/no-such-org")
    assert r.status_code == 404
    body = r.json()
    # coverage is UNAVAILABLE for an org the instance holds no data for:
    # zero would claim a measured, fully-uncovered agent fleet.
    assert body["org"] == "no-such-org"
    assert "never zero" in body["error"]
    assert body["known_orgs"] == ["demo"]
    assert "receipted_share" not in body
    assert "breakdown" not in body


def test_org_override_ids_the_instance(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    monkeypatch.setenv("OAA_COVERAGE_ORG", "acme")
    assert _coverage_org() == "acme"
    d = tmp_path
    shutil.copytree(DATA_DIR, d, dirs_exist_ok=True)
    client = TestClient(create_app(d))
    ok = client.get("/coverage/acme")
    assert ok.status_code == 200
    assert ok.json()["org"] == "acme"
    missing = client.get("/coverage/demo")
    assert missing.status_code == 404
    assert missing.json()["known_orgs"] == ["acme"]


def test_hostile_org_segment_is_data_not_markup(client: TestClient) -> None:
    # a hostile path segment reaches the response only as a JSON string
    # value (quoted/escaped by the serialiser, JSON content-type) — it is
    # returned as data, never interpreted as route markup or rendered HTML
    hostile = 'no-such-org"><script>'
    r = client.get(f"/coverage/{hostile}")
    assert r.status_code == 404
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["org"] == hostile
    assert r.json()["error"].endswith("coverage is unavailable here, never zero")
