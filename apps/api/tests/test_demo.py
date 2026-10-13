"""Demo scenarios run through the real pipeline; expected detections are asserted."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from aegis.demo import runner
from tests.conftest import Api, event, ingest


def run(admin: Api, scenario: str) -> dict[str, object]:
    response = admin.post("/api/v1/demo/run", json={"scenario": scenario})
    assert response.status_code == 202, response.text
    return dict(response.json())


def rules_fired(admin: Api) -> set[str]:
    items = admin.get("/api/v1/alerts", params={"scope": "demo", "limit": 500}).json()["items"]
    return {a["rule_id"] for a in items}


def test_scenarios_are_listed(admin: Api) -> None:
    ids = {s["id"] for s in admin.get("/api/v1/demo/scenarios").json()}
    assert {"ssh-intrusion", "webshell-miner", "baseline-benign"} <= ids


def test_ssh_intrusion_detections(admin: Api) -> None:
    sim = run(admin, "ssh-intrusion")
    assert sim["status"] == "completed"
    scenario = runner.available()["ssh-intrusion"]
    expected = set(scenario.expected["rules"])
    fired = rules_fired(admin)
    assert expected <= fired, f"missing: {expected - fired}"
    incidents = admin.get("/api/v1/incidents", params={"scope": "demo"}).json()["items"]
    assert incidents, "high severity detections must open an incident"
    assert all(i["is_synthetic"] for i in incidents)
    # Live views do not show demo data.
    assert admin.get("/api/v1/alerts").json()["total"] == 0
    assert admin.get("/api/v1/events").json()["total"] == 0


def test_webshell_miner_detections(admin: Api) -> None:
    run(admin, "webshell-miner")
    expected = set(runner.available()["webshell-miner"].expected["rules"])
    assert expected <= rules_fired(admin)


def test_baseline_has_no_false_positives(admin: Api) -> None:
    sim = run(admin, "baseline-benign")
    assert sim["events_sent"] > 50
    assert rules_fired(admin) == set()


def test_runs_are_reproducible(admin: Api, db: Session) -> None:
    from aegis.demo.scenarios import expand

    scenario = runner.available()["ssh-intrusion"]
    from datetime import UTC, datetime

    anchor = datetime(2026, 1, 1, tzinfo=UTC)
    assert expand(scenario, anchor, seed=7) == expand(scenario, anchor, seed=7)
    assert expand(scenario, anchor, seed=7) != expand(scenario, anchor, seed=8)


def test_reset_removes_only_synthetic_data(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    ingest(app_client, agent_token, [event()])
    run(admin, "webshell-miner")
    assert admin.get("/api/v1/events", params={"scope": "demo"}).json()["total"] > 0
    counts = admin.post("/api/v1/demo/reset").json()
    assert counts["events"] > 0
    assert admin.get("/api/v1/events", params={"scope": "demo"}).json()["total"] == 0
    assert admin.get("/api/v1/alerts", params={"scope": "demo"}).json()["total"] == 0
    assert admin.get("/api/v1/events").json()["total"] == 1
    assert admin.get("/api/v1/endpoints").json()[0]["hostname"] == "host-a"
