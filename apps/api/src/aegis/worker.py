"""Detection worker: consumes event ids from Redis Streams and runs the detection engine.

Run with ``aegis worker``. Several workers can share the consumer group; each message is
delivered to one of them and acknowledged only after detection results are committed.
"""

from __future__ import annotations

import contextlib
import logging
import os
import signal
import socket
import uuid

from sqlalchemy import select

from aegis.db import session_factory
from aegis.detection.registry import registry
from aegis.events.broker import BrokerUnavailable, StreamBroker
from aegis.events.pipeline import run_detection
from aegis.models import Event
from aegis.observability import configure_logging, metrics

log = logging.getLogger("aegis.worker")


def run_forever() -> None:
    configure_logging()
    consumer = f"{socket.gethostname()}-{os.getpid()}"
    broker = StreamBroker()
    broker.ensure_group()
    stopping = False

    def _stop(*_: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    with session_factory()() as db:
        registry.bootstrap(db)
    log.info("detection worker started", extra={"path": consumer})
    while not stopping:
        try:
            messages = broker.read(consumer)
        except BrokerUnavailable:
            log.warning("broker unavailable; retrying")
            continue
        except Exception:
            log.exception("broker read failed")
            continue
        if not messages:
            continue
        ids = [uuid.UUID(i) for _, chunk in messages for i in chunk if i]
        with session_factory()() as db:
            events = list(db.scalars(select(Event).where(Event.id.in_(ids))))
            result = run_detection(db, events, trigger="worker")
        broker.ack([mid for mid, _ in messages])
        with contextlib.suppress(BrokerUnavailable):
            metrics.BROKER_LAG.set(broker.backlog())
        log.info(
            "batch processed", extra={"path": f"events={len(events)} matches={result.matches}"}
        )
    log.info("detection worker stopped")
