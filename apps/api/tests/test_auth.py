"""Authentication, sessions, CSRF, MFA and abuse protection."""

from __future__ import annotations

import time

import pyotp
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from aegis.models import AuditLog
from tests.conftest import PASSWORD, login, make_user


def test_login_sets_httponly_cookie_and_me_works(app_client: TestClient, db: Session) -> None:
    user = make_user(db, "analyst")
    response = app_client.post(
        "/api/v1/auth/login", json={"email": user.email.upper(), "password": PASSWORD}
    )
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=lax" in cookie
    me = app_client.get("/api/v1/auth/me").json()
    assert me["email"] == user.email
    assert me["role"] == "analyst"
    assert "incidents:write" in me["permissions"]
    assert "users:manage" not in me["permissions"]


def test_wrong_password_is_generic_and_audited(app_client: TestClient, db: Session) -> None:
    user = make_user(db, "viewer")
    bad = app_client.post("/api/v1/auth/login", json={"email": user.email, "password": "nope"})
    unknown = app_client.post(
        "/api/v1/auth/login", json={"email": "ghost@aegis.lab", "password": "nope"}
    )
    assert bad.status_code == unknown.status_code == 401
    assert bad.json() == unknown.json() == {"detail": "invalid credentials"}
    entries = db.query(AuditLog).filter(AuditLog.action == "auth.login").all()
    assert {e.outcome for e in entries} == {"failure"}
    assert all("password" not in str(e.details) for e in entries)


def test_account_lockout_and_throttling(app_client: TestClient, db: Session) -> None:
    user = make_user(db, "viewer")
    for _ in range(5):
        app_client.post("/api/v1/auth/login", json={"email": user.email, "password": "wrong"})
    # correct password is refused while the window is saturated
    response = app_client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": PASSWORD}
    )
    assert response.status_code == 429
    assert "retry-after" in response.headers


def test_csrf_required_for_cookie_mutations(app_client: TestClient, db: Session) -> None:
    user = make_user(db, "administrator")
    api = login(app_client, user.email)
    no_header = app_client.post("/api/v1/agents", json={"name": "x-agent"})
    assert no_header.status_code == 403
    assert "CSRF" in no_header.json()["detail"]
    wrong = app_client.post(
        "/api/v1/agents", json={"name": "x-agent"}, headers={"x-csrf-token": "forged"}
    )
    assert wrong.status_code == 403
    assert api.post("/api/v1/agents", json={"name": "x-agent"}).status_code == 201


def test_logout_revokes_session(app_client: TestClient, db: Session) -> None:
    user = make_user(db, "viewer")
    api = login(app_client, user.email)
    assert api.post("/api/v1/auth/logout").status_code == 204
    assert app_client.get("/api/v1/auth/me").status_code == 401


def test_session_list_and_revoke_other_session(app_client: TestClient, db: Session) -> None:
    user = make_user(db, "viewer")
    other = TestClient(app_client.app, base_url="http://testserver")
    login(other, user.email)
    api = login(app_client, user.email)
    sessions = api.get("/api/v1/auth/sessions").json()
    assert len(sessions) == 2
    target = next(s for s in sessions if not s["current"])
    assert api.delete(f"/api/v1/auth/sessions/{target['id']}").status_code == 204
    assert other.get("/api/v1/auth/me").status_code == 401
    assert app_client.get("/api/v1/auth/me").status_code == 200


def test_mfa_enrolment_and_login(app_client: TestClient, db: Session) -> None:
    user = make_user(db, "analyst")
    api = login(app_client, user.email)
    setup = api.post("/api/v1/auth/mfa/setup").json()
    totp = pyotp.TOTP(setup["secret"])
    assert setup["otpauth_uri"].startswith("otpauth://totp/AEGIS")
    assert api.post("/api/v1/auth/mfa/enable", json={"code": "000000"}).status_code == 400
    assert api.post("/api/v1/auth/mfa/enable", json={"code": totp.now()}).status_code == 204

    fresh = TestClient(app_client.app, base_url="http://testserver")
    first = fresh.post("/api/v1/auth/login", json={"email": user.email, "password": PASSWORD})
    assert first.json()["mfa_required"] is True
    # a pending session cannot access the API
    assert fresh.get("/api/v1/auth/me").status_code == 401
    csrf = first.json()["csrf_token"]
    # the code used for enrolment cannot be replayed
    replay = fresh.post(
        "/api/v1/auth/mfa/verify", json={"code": totp.now()}, headers={"x-csrf-token": csrf}
    )
    assert replay.status_code == 401
    next_code = totp.at(time.time() + 30)
    ok = fresh.post(
        "/api/v1/auth/mfa/verify", json={"code": next_code}, headers={"x-csrf-token": csrf}
    )
    assert ok.status_code == 200, ok.text
    assert fresh.get("/api/v1/auth/me").json()["mfa_enabled"] is True


def test_password_change_policy_and_rotation(app_client: TestClient, db: Session) -> None:
    user = make_user(db, "viewer")
    other = TestClient(app_client.app, base_url="http://testserver")
    login(other, user.email)
    api = login(app_client, user.email)
    weak = api.post(
        "/api/v1/auth/password", json={"current_password": PASSWORD, "new_password": "short"}
    )
    assert weak.status_code == 422
    ok = api.post(
        "/api/v1/auth/password",
        json={"current_password": PASSWORD, "new_password": "a much longer passphrase"},
    )
    assert ok.status_code == 204
    assert other.get("/api/v1/auth/me").status_code == 401  # other sessions revoked
    assert app_client.get("/api/v1/auth/me").status_code == 200


def test_bearer_token_api_access_without_csrf(app_client: TestClient, db: Session) -> None:
    user = make_user(db, "administrator")
    response = app_client.post(
        "/api/v1/auth/login", json={"email": user.email, "password": PASSWORD}
    )
    token = response.cookies.get("aegis_session")
    bare = TestClient(app_client.app, base_url="http://testserver")
    created = bare.post(
        "/api/v1/agents", json={"name": "scripted"}, headers={"authorization": f"Bearer {token}"}
    )
    assert created.status_code == 201
