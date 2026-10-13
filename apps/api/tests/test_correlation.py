"""Correlation rules over durable rule matches, including out-of-order delivery."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient

from aegis.detection.engine import _max_in_window, _ordered_sequence
from tests.conftest import Api, event, ingest


def failure(at: datetime, source: str = "203.0.113.9", user: str = "root") -> dict[str, object]:
    return event(
        category="authentication",
        action="login_failure",
        occurred_at=at,
        user={"name": user},
        auth={
            "method": "password",
            "outcome": "failure",
            "source_ip": source,
            "target_user": user,
            "service": "sshd",
        },
    )


def success(at: datetime, source: str = "203.0.113.9") -> dict[str, object]:
    return event(
        category="authentication",
        action="login_success",
        occurred_at=at,
        user={"name": "deploy"},
        auth={
            "method": "password",
            "outcome": "success",
            "source_ip": source,
            "target_user": "deploy",
            "service": "sshd",
        },
    )


def rule_alerts(admin: Api, rule_id: str) -> list[dict[str, object]]:
    return admin.get("/api/v1/alerts", params={"rule_id": rule_id}).json()["items"]


def test_bruteforce_threshold(app_client: TestClient, admin: Api, agent_token: str) -> None:
    base = datetime.now(UTC) - timedelta(minutes=20)
    nine = [failure(base + timedelta(seconds=10 * i)) for i in range(9)]
    ingest(app_client, agent_token, nine)
    assert rule_alerts(admin, "aegis-corr-ssh-bruteforce") == []
    ingest(app_client, agent_token, [failure(base + timedelta(seconds=95))])
    alerts = rule_alerts(admin, "aegis-corr-ssh-bruteforce")
    assert len(alerts) == 1
    assert alerts[0]["context"]["observed"] == 10
    assert alerts[0]["context"]["group_by"] == {
        "auth.source_ip": "203.0.113.9",
        "host.hostname": "host-a",
    }


def test_bruteforce_out_of_order_and_outside_window(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    base = datetime.now(UTC) - timedelta(minutes=50)
    # Ten failures spread over 20 minutes never fit in a 5 minute window.
    spread = [failure(base + timedelta(minutes=2 * i)) for i in range(10)]
    ingest(app_client, agent_token, list(reversed(spread)))
    assert rule_alerts(admin, "aegis-corr-ssh-bruteforce") == []
    # A delayed batch fills the gap around the 5th event -> threshold reached.
    late = [failure(base + timedelta(minutes=8, seconds=5 * i)) for i in range(8)]
    ingest(app_client, agent_token, late)
    assert len(rule_alerts(admin, "aegis-corr-ssh-bruteforce")) == 1


def test_groups_are_independent(app_client: TestClient, admin: Api, agent_token: str) -> None:
    base = datetime.now(UTC) - timedelta(minutes=10)
    events = [failure(base + timedelta(seconds=i), source=f"203.0.113.{i}") for i in range(12)]
    ingest(app_client, agent_token, events)
    assert rule_alerts(admin, "aegis-corr-ssh-bruteforce") == []


def test_password_spray_value_count(app_client: TestClient, admin: Api, agent_token: str) -> None:
    base = datetime.now(UTC) - timedelta(minutes=10)
    events = [failure(base + timedelta(seconds=20 * i), user=f"user{i}") for i in range(5)]
    ingest(app_client, agent_token, events)
    assert len(rule_alerts(admin, "aegis-corr-ssh-password-spray")) == 1


def test_temporal_ordered_requires_order(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    base = datetime.now(UTC) - timedelta(minutes=30)
    # success BEFORE failure: no alert
    ingest(app_client, agent_token, [success(base), failure(base + timedelta(minutes=1))])
    assert rule_alerts(admin, "aegis-corr-ssh-success-after-failures") == []
    # failure then success: alert
    ingest(
        app_client,
        agent_token,
        [failure(base + timedelta(minutes=10)), success(base + timedelta(minutes=12))],
    )
    assert len(rule_alerts(admin, "aegis-corr-ssh-success-after-failures")) == 1


def test_repeated_firing_is_aggregated(
    app_client: TestClient, admin: Api, agent_token: str
) -> None:
    base = datetime.now(UTC) - timedelta(minutes=10)
    ingest(app_client, agent_token, [failure(base + timedelta(seconds=i)) for i in range(25)])
    alerts = rule_alerts(admin, "aegis-corr-ssh-bruteforce")
    assert len(alerts) == 1
    assert alerts[0]["hit_count"] == 25


def test_window_helpers() -> None:
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    times = [t0 + timedelta(minutes=m) for m in (0, 1, 2, 10, 11)]
    span = timedelta(minutes=2)
    assert _max_in_window(times, t0 + timedelta(minutes=1), span) == 3
    assert _max_in_window(times, t0 + timedelta(minutes=10), span) == 2
    a = [(t0, "a1"), (t0 + timedelta(minutes=5), "a2")]
    b = [(t0 + timedelta(minutes=6), "b1")]
    assert _ordered_sequence([a, b], span, "b1") == ["a2", "b1"]  # type: ignore[list-item]
    assert _ordered_sequence([b, a], span, "b1") is None  # type: ignore[list-item]
