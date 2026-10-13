"""Event broker on Redis Streams.

Events are persisted *before* they are published, so the stream only carries event ids. A
consumer group gives at-least-once delivery: messages stay pending until acknowledged and are
reclaimed after a crash. Because detection is idempotent per (rule, event), redelivery is safe.

Redis Streams was chosen over Kafka/Redpanda for the MVP (see docs/adr/0003-event-broker.md):
it provides consumer groups, acknowledgements and replay with one lightweight service that is
already needed for realtime fan-out and rate limiting.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Iterable
from typing import Any

import redis

from aegis.config import get_settings

log = logging.getLogger(__name__)
GROUP = "detection"


class BrokerUnavailable(RuntimeError):
    pass


class Backpressure(RuntimeError):
    pass


class StreamBroker:
    def __init__(self, url: str | None = None, stream: str | None = None) -> None:
        settings = get_settings()
        target = url or settings.redis_url
        if not target:
            raise BrokerUnavailable("AEGIS_REDIS_URL is required in broker mode")
        self.client = redis.Redis.from_url(target, decode_responses=True)
        self.stream = stream or settings.stream_name
        self.max_pending = settings.stream_max_pending

    def ensure_group(self) -> None:
        try:
            self.client.xgroup_create(self.stream, GROUP, id="0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def backlog(self) -> int:
        try:
            self.ensure_group()
            info = self.client.xinfo_groups(self.stream)
        except redis.RedisError as exc:
            raise BrokerUnavailable(str(exc)) from exc
        for group in info:
            if group.get("name") == GROUP:
                lag = group.get("lag")
                pending = int(group.get("pending") or 0)
                return pending + int(lag if lag is not None else self.client.xlen(self.stream))
        return int(self.client.xlen(self.stream))

    def check_capacity(self) -> None:
        if self.backlog() >= self.max_pending:
            raise Backpressure("detection backlog is full")

    def publish(self, event_ids: Iterable[uuid.UUID]) -> int:
        ids = [str(i) for i in event_ids]
        if not ids:
            return 0
        try:
            # One message per event keeps acknowledgement and backlog accounting per event.
            # Approximate trimming bounds memory; ingestion refuses work well before that.
            pipe = self.client.pipeline(transaction=False)
            for event_id in ids:
                pipe.xadd(
                    self.stream, {"id": event_id}, maxlen=self.max_pending * 4, approximate=True
                )
            pipe.execute()
        except redis.RedisError as exc:
            raise BrokerUnavailable(str(exc)) from exc
        return len(ids)

    def read(
        self, consumer: str, count: int = 200, block_ms: int = 2000, reclaim_idle_ms: int = 60_000
    ) -> list[tuple[str, list[str]]]:
        self.ensure_group()
        # First reclaim messages abandoned by crashed consumers.
        claimed: Any = self.client.xautoclaim(
            self.stream, GROUP, consumer, min_idle_time=reclaim_idle_ms, start_id="0-0", count=count
        )
        messages: Any = claimed[1] if claimed else []
        if not messages:
            response: Any = self.client.xreadgroup(
                GROUP, consumer, {self.stream: ">"}, count=count, block=block_ms
            )
            messages = response[0][1] if response else []
        return [
            (str(mid), [str(fields["id"])]) for mid, fields in messages if fields and "id" in fields
        ]

    def ack(self, message_ids: list[str]) -> None:
        if message_ids:
            self.client.xack(self.stream, GROUP, *message_ids)
