"""Test fixtures.

By default tests run on a temporary SQLite database (zero infrastructure). Set
``AEGIS_TEST_DATABASE_URL`` to run the same suite against PostgreSQL (CI does both).
The schema is always created through the Alembic migrations, so migrations are tested too.
"""

from __future__ import annotations

import os
import secrets
import tempfile
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
_tmp = tempfile.mkdtemp(prefix="aegis-test-")
os.environ.setdefault("AEGIS_SECRET_KEY", secrets.token_urlsafe(48))
os.environ["AEGIS_ENVIRONMENT"] = "test"
os.environ["AEGIS_DATABASE_URL"] = os.environ.get(
    "AEGIS_TEST_DATABASE_URL", f"sqlite:///{_tmp}/aegis-test.db"
)
os.environ["AEGIS_RULES_DIR"] = str(ROOT / "rules")
os.environ["AEGIS_SCENARIOS_DIR"] = str(ROOT / "simulations" / "scenarios")
os.environ["AEGIS_COOKIE_SECURE"] = "false"
os.environ["AEGIS_PIPELINE_MODE"] = "inline"
os.environ.pop("AEGIS_REDIS_URL", None)

from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402

from aegis.db import Base, get_engine, session_factory  # noqa: E402
from aegis.detection.registry import registry  # noqa: E402
from aegis.main import create_app  # noqa: E402
from aegis.migrations import upgrade_head  # noqa: E402
from aegis.models import Role, User  # noqa: E402
from aegis.security.crypto import hash_password  # noqa: E402
from aegis.security.rbac import ROLE_DESCRIPTIONS  # noqa: E402

PASSWORD = "correct horse battery staple"


@pytest.fixture(scope="session", autouse=True)
def _schema() -> Iterator[None]:
    engine = get_engine()
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            conn.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public;"))
    upgrade_head()
    yield


@pytest.fixture(autouse=True)
def _clean() -> Iterator[None]:
    yield
    engine = get_engine()
    tables = [t for t in reversed(Base.metadata.sorted_tables)]
    with engine.begin() as conn:
        if engine.dialect.name == "postgresql":
            names = ", ".join(t.name for t in tables)
            conn.execute(text(f"TRUNCATE {names} RESTART IDENTITY CASCADE"))
        else:
            for table in tables:
                conn.execute(table.delete())
    registry._fingerprint = None  # force a reload for the next test


@pytest.fixture
def db() -> Iterator[Session]:
    session = session_factory()()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def app_client() -> Iterator[TestClient]:
    with TestClient(create_app(), base_url="http://testserver") as client:
        yield client


def _seed_roles(db: Session) -> None:
    for name, description in ROLE_DESCRIPTIONS.items():
        if db.get(Role, name) is None:
            db.add(Role(name=name, description=description))
    db.commit()


def make_user(db: Session, role: str, email: str | None = None) -> User:
    _seed_roles(db)
    user = User(
        email=email or f"{role}-{uuid.uuid4().hex[:6]}@aegis.test",
        display_name=role.title(),
        role=role,
        password_hash=hash_password(PASSWORD),
    )
    db.add(user)
    db.commit()
    return user


class Api:
    """Thin wrapper that logs in and attaches the CSRF header automatically."""

    def __init__(self, client: TestClient, csrf: str) -> None:
        self.client = client
        self.csrf = csrf

    def get(self, url: str, **kw: Any) -> Any:
        return self.client.get(url, **kw)

    def post(self, url: str, **kw: Any) -> Any:
        return self.client.post(url, headers={"x-csrf-token": self.csrf}, **kw)

    def patch(self, url: str, **kw: Any) -> Any:
        return self.client.patch(url, headers={"x-csrf-token": self.csrf}, **kw)

    def delete(self, url: str, **kw: Any) -> Any:
        return self.client.delete(url, headers={"x-csrf-token": self.csrf}, **kw)


def login(client: TestClient, email: str, password: str = PASSWORD) -> Api:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return Api(client, response.json()["csrf_token"])


@pytest.fixture
def admin(app_client: TestClient, db: Session) -> Api:
    user = make_user(db, "administrator")
    return login(app_client, user.email)


@pytest.fixture
def agent_token(admin: Api) -> str:
    response = admin.post("/api/v1/agents", json={"name": "test-agent"})
    assert response.status_code == 201, response.text
    return str(response.json()["token"])


def event(
    *,
    category: str = "process",
    action: str = "start",
    hostname: str = "host-a",
    occurred_at: datetime | None = None,
    **sections: Any,
) -> dict[str, Any]:
    """Build a valid ACE v1 event with sensible defaults."""
    body: dict[str, Any] = {
        "schema_version": "1.0",
        "event_id": str(uuid.uuid4()),
        "occurred_at": (occurred_at or datetime.now(UTC) - timedelta(seconds=5)).isoformat(),
        "category": category,
        "action": action,
        "host": {"hostname": hostname, "os": "Linux", "ip": ["10.0.0.5"]},
    }
    if category == "process" and "process" not in sections:
        sections["process"] = {
            "pid": 4242,
            "ppid": 1,
            "name": "ls",
            "executable": "/usr/bin/ls",
            "command_line": "ls -la",
        }
    body.update(sections)
    return body


def ingest(client: TestClient, token: str, events: list[dict[str, Any]]) -> Any:
    return client.post(
        "/api/v1/ingest/events",
        json={"events": events},
        headers={"authorization": f"Bearer {token}"},
    )
