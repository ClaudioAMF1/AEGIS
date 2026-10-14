"""Agent-facing endpoints: telemetry ingestion and heartbeats."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from aegis.config import PipelineMode, get_settings
from aegis.db import utcnow
from aegis.events import pipeline
from aegis.events.broker import Backpressure, BrokerUnavailable, StreamBroker
from aegis.events.contract import HeartbeatIn, HeartbeatOut, IngestResult, PendingAction
from aegis.models import Endpoint, ResponseAction, ResponseStatus
from aegis.security.deps import CurrentAgent, DbSession

router = APIRouter(prefix="/ingest", tags=["ingest"])


async def _read_json(request: Request) -> Any:
    settings = get_settings()
    declared = int(request.headers.get("content-length") or 0)
    if declared > settings.ingest_max_body_bytes:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "request body too large")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > settings.ingest_max_body_bytes:
            raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "request body too large")
    try:
        return json.loads(body)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "body is not valid JSON") from exc


@router.post("/events", response_model=IngestResult)
async def ingest_events(request: Request, agent: CurrentAgent, db: DbSession) -> IngestResult:
    """Accept a batch of ACE v1 events. Valid events are stored even if others are rejected;
    the response lists rejected indexes so the agent can drop them instead of retrying."""
    settings = get_settings()
    body = await _read_json(request)
    if not isinstance(body, dict) or not isinstance(body.get("events"), list):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "expected {'events': [...]}")
    events = body["events"]
    if not events or len(events) > settings.ingest_max_batch:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"batch must contain 1..{settings.ingest_max_batch} events",
        )
    if settings.pipeline_mode == PipelineMode.BROKER:
        try:
            StreamBroker().check_capacity()
        except Backpressure as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, str(exc), headers={"Retry-After": "10"}
            ) from exc
        except BrokerUnavailable as exc:
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE,
                "broker unavailable",
                headers={"Retry-After": "5"},
            ) from exc
    buffer_depth = body.get("buffer_depth")
    agent_version = body.get("agent_version")
    outcome = await run_in_threadpool(
        pipeline.ingest,
        db,
        agent,
        events,
        agent_version=str(agent_version)[:32] if agent_version else None,
        buffer_depth=int(buffer_depth) if isinstance(buffer_depth, int) else None,
    )
    return outcome.result


@router.post("/heartbeat", response_model=HeartbeatOut)
def heartbeat(body: HeartbeatIn, agent: CurrentAgent, db: DbSession) -> HeartbeatOut:
    now = utcnow()
    agent.last_heartbeat_at = now
    agent.version = body.agent_version
    agent.buffer_depth = body.buffer_depth
    if agent.endpoint_id is None:
        created = pipeline.get_or_create_endpoint(
            db, body.host.hostname, agent.is_synthetic, body.host.os, body.host.ip
        )
        agent.endpoint_id = created.id
        agent.status = "active"
    endpoint = db.get(Endpoint, agent.endpoint_id)
    if endpoint is not None:
        if endpoint.hostname != body.host.hostname:
            raise HTTPException(status.HTTP_409_CONFLICT, "agent is bound to a different host")
        endpoint.last_seen_at = now
        endpoint.os = body.host.os or endpoint.os
        endpoint.ip_addresses = body.host.ip or endpoint.ip_addresses
    # Approved lab actions targeting this endpoint are delivered on the heartbeat.
    pending = db.scalars(
        select(ResponseAction).where(
            ResponseAction.target_type == "endpoint",
            ResponseAction.target_id == str(agent.endpoint_id),
            ResponseAction.status == ResponseStatus.APPROVED.value,
        )
    ).all()
    db.commit()
    return HeartbeatOut(
        server_time=now,
        config=agent.config or {},
        pending_actions=[
            PendingAction(
                id=str(a.id),
                action_type=a.action_type,
                parameters={"incident_id": str(a.incident_id) if a.incident_id else None},
            )
            for a in pending
        ],
    )
