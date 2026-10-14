"""Threat intelligence and response actions."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from aegis.config import get_settings
from tests.conftest import Api, event, ingest, login, make_user


def test_indicator_crud_import_and_enrichment(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    created = admin.post(
        "/api/v1/intel/indicators",
        json={"value": "198.51.100.99", "severity": "high", "confidence": 80, "source": "lab-feed"},
    )
    assert created.status_code == 201 and created.json()["type"] == "ipv4"
    bad = admin.post("/api/v1/intel/indicators", json={"value": "not an indicator!"})
    assert bad.status_code == 422
    imported = admin.post(
        "/api/v1/intel/indicators/import",
        json={
            "source": "csv-feed",
            "csv": "value,severity,confidence\n# comment\n203.0.113.0/24,medium,60\n"
            "evil.example.test\nzzz,high,1\n" + "a" * 64 + ",critical,90\n",
        },
    ).json()
    assert imported["created"] == 3 and len(imported["rejected"]) == 1

    ingest(
        app_client,
        agent_token,
        [
            event(
                category="network",
                action="connect",
                process={"pid": 3, "name": "curl"},
                network={
                    "direction": "outbound",
                    "protocol": "tcp",
                    "src_ip": "10.0.0.5",
                    "src_port": 40000,
                    "dst_ip": "198.51.100.99",
                    "dst_port": 443,
                },
            )
        ],
    )
    alert = admin.get("/api/v1/alerts").json()["items"][0]
    assert alert["rule_id"] == "aegis-intel-indicator-match"
    detail = admin.get(f"/api/v1/alerts/{alert['id']}").json()
    enriched = admin.get(f"/api/v1/events/{detail['events'][0]['id']}").json()
    assert enriched["enrichment"]["intel.source"] == "lab-feed"

    lookup = admin.get("/api/v1/intel/lookup", params={"value": "198.51.100.99"}).json()
    assert lookup["sightings"] == 1 and lookup["local_matches"][0]["hits"] == 1
    assert lookup["external"]["verdict"] in {"not_applicable", "disabled"}
    # private ranges are never sent to external providers
    private = admin.get("/api/v1/intel/lookup", params={"value": "10.1.2.3"}).json()
    assert private["external"]["verdict"] == "not_applicable"


def test_viewer_cannot_manage_indicators(app_client: TestClient, db: Session) -> None:
    viewer = login(
        TestClient(app_client.app, base_url="http://testserver"), make_user(db, "viewer").email
    )
    assert viewer.get("/api/v1/intel/indicators").status_code == 200
    assert viewer.post("/api/v1/intel/indicators", json={"value": "1.1.1.1"}).status_code == 403


@pytest.fixture
def two_admins(app_client: TestClient, db: Session) -> tuple[Api, Api]:
    first = login(
        TestClient(app_client.app, base_url="http://testserver"),
        make_user(db, "administrator").email,
    )
    second = login(
        TestClient(app_client.app, base_url="http://testserver"),
        make_user(db, "administrator").email,
    )
    return first, second


def test_disable_rule_requires_four_eyes_and_reverts(two_admins: tuple[Api, Api]) -> None:
    requester, approver = two_admins
    rule = "aegis-lnx-exec-from-tmp"
    preview = requester.post(
        "/api/v1/response/preview", json={"action_type": "disable_rule", "target_id": rule}
    ).json()
    assert preview["confirmation_text"] == rule and preview["reversible"] is True
    action = requester.post(
        "/api/v1/response/actions",
        json={
            "action_type": "disable_rule",
            "target_id": rule,
            "justification": "Noisy on build hosts during release week",
        },
    ).json()
    assert action["status"] == "proposed"
    url = f"/api/v1/response/actions/{action['id']}/decision"
    assert requester.post(url, json={"approve": True, "confirmation": rule}).status_code == 403
    assert approver.post(url, json={"approve": True, "confirmation": "wrong"}).status_code == 422
    done = approver.post(url, json={"approve": True, "confirmation": rule}).json()
    assert done["status"] == "executed" and done["result"]["enabled"] is False
    assert approver.get(f"/api/v1/detections/rules/{rule}").json()["enabled"] is False
    reverted = approver.post(f"/api/v1/response/actions/{action['id']}/revert").json()
    assert reverted["status"] == "reverted"
    assert approver.get(f"/api/v1/detections/rules/{rule}").json()["enabled"] is True
    audit = approver.get("/api/v1/audit", params={"action": "response."}).json()
    assert {e["action"] for e in audit["items"]} == {
        "response.propose",
        "response.decision",
        "response.revert",
    }


def test_host_isolation_only_for_lab_and_delivered_to_agent(
    app_client: TestClient, admin: Api, agent_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "response_allow_self_approval", True)
    ingest(app_client, agent_token, [event(hostname="lab-host")])
    endpoint = admin.get("/api/v1/endpoints").json()[0]
    body = {
        "action_type": "isolate_host_lab",
        "target_id": endpoint["id"],
        "justification": "Reverse shell observed; contain in lab",
    }
    refused = admin.post("/api/v1/response/actions", json=body)
    assert refused.status_code == 422 and "lab" in refused.json()["detail"]
    admin.patch(f"/api/v1/endpoints/{endpoint['id']}", json={"tags": ["lab"]})
    action = admin.post("/api/v1/response/actions", json=body).json()
    decided = admin.post(
        f"/api/v1/response/actions/{action['id']}/decision",
        json={"approve": True, "confirmation": "lab-host"},
    ).json()
    assert decided["status"] == "approved"  # waits for the agent

    headers = {"authorization": f"Bearer {agent_token}"}
    beat = app_client.post(
        "/api/v1/ingest/heartbeat",
        headers=headers,
        json={
            "agent_version": "0.1.0",
            "host": {"hostname": "lab-host"},
            "buffer_depth": 0,
            "uptime_seconds": 10,
        },
    ).json()
    assert beat["pending_actions"][0]["action_type"] == "isolate_host_lab"
    ack = app_client.post(
        f"/api/v1/ingest/actions/{action['id']}/result",
        headers=headers,
        json={"outcome": "simulated", "detail": "lab agent: no firewall change"},
    )
    assert ack.status_code == 200 and ack.json()["status"] == "executed"
    assert admin.get(f"/api/v1/endpoints/{endpoint['id']}").json()["isolation_state"] == (
        "isolated_simulated"
    )


def test_analyst_can_propose_but_not_approve(app_client: TestClient, db: Session) -> None:
    analyst = login(
        TestClient(app_client.app, base_url="http://testserver"), make_user(db, "analyst").email
    )
    action = analyst.post(
        "/api/v1/response/actions",
        json={
            "action_type": "disable_rule",
            "target_id": "aegis-lnx-coin-miner",
            "justification": "Authorised mining workload in lab",
        },
    )
    assert action.status_code == 201
    decision = analyst.post(
        f"/api/v1/response/actions/{action.json()['id']}/decision",
        json={"approve": True, "confirmation": "aegis-lnx-coin-miner"},
    )
    assert decision.status_code == 403


def test_reports_json_and_pdf(admin: Api) -> None:
    admin.post("/api/v1/demo/run", json={"scenario": "ssh-intrusion"})
    overview = admin.post("/api/v1/reports", json={"kind": "overview", "scope": "demo"})
    assert overview.status_code == 201
    rid = overview.json()["id"]
    content = admin.get(f"/api/v1/reports/{rid}.json").json()
    assert content["scope"] == "demo" and content["analytics"]["alerts_by_severity"]
    assert all(m["definition"] for m in content["metrics"])
    pdf = admin.get(f"/api/v1/reports/{rid}.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    incident = admin.get("/api/v1/incidents", params={"scope": "demo"}).json()["items"][0]
    inc_report = admin.post(
        "/api/v1/reports", json={"kind": "incident", "incident_id": incident["id"]}
    ).json()
    data = admin.get(f"/api/v1/reports/{inc_report['id']}.json").json()
    assert data["timeline"] and data["incident"]["number"] == incident["number"]
    assert admin.get(f"/api/v1/reports/{inc_report['id']}.pdf").content.startswith(b"%PDF")
