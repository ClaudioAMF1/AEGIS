"""Prometheus metrics and structured JSON logging."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from types import SimpleNamespace

from prometheus_client import Counter, Gauge, Histogram


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("request_id", "path", "method", "status", "duration_ms", "agent_id"):
            if hasattr(record, key):
                payload[key] = getattr(record, key)
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    logging.getLogger("uvicorn.access").disabled = True  # replaced by our request log


metrics = SimpleNamespace(
    EVENTS_INGESTED=Counter("aegis_events_ingested_total", "Events accepted", ["synthetic"]),
    EVENTS_DUPLICATE=Counter("aegis_events_duplicate_total", "Duplicate events acknowledged"),
    EVENTS_REJECTED=Counter(
        "aegis_events_rejected_total", "Events rejected by validation", ["reason"]
    ),
    INGEST_LATENCY=Histogram(
        "aegis_ingest_batch_seconds",
        "Ingestion batch latency",
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5),
    ),
    DETECTION_LATENCY=Histogram(
        "aegis_detection_batch_seconds",
        "Detection batch latency",
        buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 5),
    ),
    RULE_MATCHES=Counter("aegis_rule_matches_total", "Rule matches"),
    ALERTS_CREATED=Counter("aegis_alerts_created_total", "Alerts created", ["severity"]),
    INCIDENTS_CREATED=Counter("aegis_incidents_created_total", "Incidents opened"),
    BROKER_LAG=Gauge("aegis_broker_pending", "Events waiting in the broker"),
    HTTP_REQUESTS=Counter(
        "aegis_http_requests_total", "HTTP requests", ["method", "route", "status"]
    ),
    HTTP_LATENCY=Histogram("aegis_http_request_seconds", "HTTP latency", ["route"]),
    WS_CLIENTS=Gauge("aegis_ws_clients", "Connected realtime clients"),
)
