"""Realtime fan-out to WebSocket clients.

Single-process deployments fan out in memory. When Redis is configured, every process
publishes to a Redis channel and each API replica relays the channel to its own clients, so
alerts produced by the detection worker reach the dashboard too.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from typing import Any

import redis
import redis.asyncio as aioredis

from aegis.config import get_settings
from aegis.observability import metrics

log = logging.getLogger(__name__)
CHANNEL = "aegis.realtime"
_QUEUE_SIZE = 256


class Hub:
    def __init__(self) -> None:
        self._clients: set[asyncio.Queue[dict[str, Any]]] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._redis: redis.Redis | None = None
        self._listener: asyncio.Task[None] | None = None

    # -- lifecycle -------------------------------------------------------
    async def start(self) -> None:
        self._loop = asyncio.get_running_loop()
        url = get_settings().redis_url
        if url:
            self._redis = redis.Redis.from_url(url)
            self._listener = asyncio.create_task(self._relay(url))

    async def stop(self) -> None:
        if self._listener:
            self._listener.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._listener

    async def _relay(self, url: str) -> None:
        while True:
            try:
                client = aioredis.Redis.from_url(url)
                pubsub = client.pubsub()
                await pubsub.subscribe(CHANNEL)
                async for message in pubsub.listen():
                    if message.get("type") == "message":
                        self._fanout(json.loads(message["data"]))
            except asyncio.CancelledError:
                raise
            except Exception:
                log.warning("realtime relay lost Redis connection; retrying", exc_info=True)
                await asyncio.sleep(2)

    # -- clients ---------------------------------------------------------
    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=_QUEUE_SIZE)
        self._clients.add(queue)
        metrics.WS_CLIENTS.set(len(self._clients))
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        self._clients.discard(queue)
        metrics.WS_CLIENTS.set(len(self._clients))

    def _fanout(self, message: dict[str, Any]) -> None:
        for queue in list(self._clients):
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # Slow consumer: drop the oldest message rather than blocking producers.
                with contextlib.suppress(asyncio.QueueEmpty):
                    queue.get_nowait()
                queue.put_nowait({"type": "resync"})

    # -- publishing (callable from any thread or process) -----------------
    def publish(self, message: dict[str, Any]) -> None:
        url = get_settings().redis_url
        if url:
            try:
                if self._redis is None:
                    self._redis = redis.Redis.from_url(url)
                self._redis.publish(CHANNEL, json.dumps(message, default=str))
                return
            except redis.RedisError:
                log.warning("realtime publish failed; falling back to local fan-out")
        if self._loop is not None and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._fanout, message)


hub = Hub()
