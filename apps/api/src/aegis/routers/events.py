"""Event exploration, entity graph and realtime stream."""

from __future__ import annotations

import asyncio
import contextlib
import uuid
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Query, WebSocket, WebSocketDisconnect
from sqlalchemy import and_, func, or_, select

from aegis.config import get_settings
from aegis.db import session_factory, utcnow
from aegis.events.contract import Category
from aegis.models import Alert, AlertEvent, Event, RuleMatch
from aegis.realtime import hub
from aegis.routers.common import decode_cursor, encode_cursor, not_found, scope_clause
from aegis.schemas import EventDetail, EventOut, Graph, Page, Scope
from aegis.security import sessions
from aegis.security.deps import DbSession, Principal, require
from aegis.security.rbac import Permission
from aegis.services.investigation import entity_graph

router = APIRouter(tags=["events"])
Reader = Annotated[Principal, Depends(require(Permission.TELEMETRY_READ))]


@router.get("/events", response_model=Page[EventOut])
def search_events(
    _: Reader,
    db: DbSession,
    scope: Scope = Scope.LIVE,
    start: datetime | None = None,
    end: datetime | None = None,
    category: Category | None = None,
    action: Annotated[str | None, Query(max_length=32)] = None,
    endpoint_id: uuid.UUID | None = None,
    hostname: Annotated[str | None, Query(max_length=255)] = None,
    user: Annotated[str | None, Query(max_length=128)] = None,
    process: Annotated[str | None, Query(max_length=255)] = None,
    ip: Annotated[str | None, Query(max_length=64)] = None,
    port: Annotated[int | None, Query(ge=0, le=65535)] = None,
    q: Annotated[str | None, Query(max_length=200)] = None,
    dataset: Annotated[str | None, Query(max_length=64)] = None,
    flagged: bool | None = None,
    cursor: str | None = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
) -> Page[EventOut]:
    filters = [scope_clause(Event.is_synthetic, scope)]
    if start:
        filters.append(Event.occurred_at >= start)
    if end:
        filters.append(Event.occurred_at <= end)
    if category:
        filters.append(Event.category == category.value)
    if action:
        filters.append(Event.action == action)
    if endpoint_id:
        filters.append(Event.endpoint_id == endpoint_id)
    if hostname:
        filters.append(Event.hostname == hostname)
    if user:
        filters.append(Event.user_name == user)
    if process:
        filters.append(Event.process_name == process)
    if ip:
        filters.append(or_(Event.src_ip == ip, Event.dst_ip == ip))
    if port is not None:
        filters.append(Event.dst_port == port)
    if dataset:
        filters.append(Event.dataset == dataset)
    if q:
        # Parameterised LIKE with escaped wildcards: user input never becomes SQL.
        escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        filters.append(Event.summary.ilike(f"%{escaped}%", escape="\\"))
    if flagged is not None:
        matched = select(RuleMatch.event_id)
        filters.append(Event.id.in_(matched) if flagged else Event.id.not_in(matched))
    total = db.scalar(select(func.count()).select_from(Event).where(*filters))
    stmt = select(Event).where(*filters)
    if cursor:
        ts, ident = decode_cursor(cursor)
        stmt = stmt.where(
            or_(Event.occurred_at < ts, and_(Event.occurred_at == ts, Event.id < ident))
        )
    rows = db.scalars(
        stmt.order_by(Event.occurred_at.desc(), Event.id.desc()).limit(limit + 1)
    ).all()
    next_cursor = None
    if len(rows) > limit:
        rows = rows[:limit]
        next_cursor = encode_cursor(rows[-1].occurred_at, rows[-1].id)
    return Page(
        items=[EventOut.model_validate(r) for r in rows], total=total, next_cursor=next_cursor
    )


@router.get("/events/{event_id}", response_model=EventDetail)
def get_event(event_id: uuid.UUID, _: Reader, db: DbSession) -> EventDetail:
    event = db.get(Event, event_id)
    if event is None:
        raise not_found("event")
    alert_ids = list(db.scalars(select(AlertEvent.alert_id).where(AlertEvent.event_id == event_id)))
    rule_ids = list(db.scalars(select(RuleMatch.rule_id).where(RuleMatch.event_id == event_id)))
    return EventDetail.model_validate(event).model_copy(
        update={"alert_ids": alert_ids, "rule_ids": rule_ids}
    )


@router.get("/events-histogram")
def histogram(
    _: Reader,
    db: DbSession,
    scope: Scope = Scope.LIVE,
    hours: Annotated[int, Query(ge=1, le=720)] = 24,
    buckets: Annotated[int, Query(ge=6, le=240)] = 48,
) -> dict[str, object]:
    """Event counts per time bucket and category (computed in Python for SQL portability)."""
    end = utcnow()
    start = end - timedelta(hours=hours)
    width = (end - start) / buckets
    rows = db.execute(
        select(Event.occurred_at, Event.category)
        .where(
            scope_clause(Event.is_synthetic, scope),
            Event.occurred_at >= start,
            Event.occurred_at <= end,
        )
        .limit(200_000)
    ).all()
    series: list[dict[str, object]] = [
        {
            "start": (start + width * i).isoformat(),
            "process": 0,
            "network": 0,
            "file": 0,
            "authentication": 0,
            "system": 0,
        }
        for i in range(buckets)
    ]
    for occurred_at, category in rows:
        index = min(int((occurred_at - start) / width), buckets - 1)
        bucket = series[index]
        bucket[category] = int(bucket.get(category, 0)) + 1  # type: ignore[call-overload]
    return {"start": start, "end": end, "bucket_seconds": width.total_seconds(), "series": series}


@router.get("/graph", response_model=Graph)
def graph(
    _: Reader,
    db: DbSession,
    scope: Scope = Scope.LIVE,
    start: datetime | None = None,
    end: datetime | None = None,
    endpoint_id: uuid.UUID | None = None,
    only_flagged: bool = False,
    limit: Annotated[int, Query(ge=10, le=5000)] = 1500,
) -> Graph:
    end = end or utcnow()
    start = start or end - timedelta(hours=24)
    filters = [
        scope_clause(Event.is_synthetic, scope),
        Event.occurred_at >= start,
        Event.occurred_at <= end,
    ]
    if endpoint_id:
        filters.append(Event.endpoint_id == endpoint_id)
    if only_flagged:
        flagged_events = select(AlertEvent.event_id)
        flagged_hosts = select(Alert.endpoint_id).where(Alert.id.in_(select(AlertEvent.alert_id)))
        filters.append(or_(Event.id.in_(flagged_events), Event.endpoint_id.in_(flagged_hosts)))
    events = db.scalars(
        select(Event).where(*filters).order_by(Event.occurred_at.desc()).limit(limit)
    ).all()
    result = entity_graph(db, list(reversed(events)))
    result.window = {"start": start, "end": end}
    return result


def _session_alive(token: str) -> bool:
    db = session_factory()()
    try:
        record = sessions.resolve(db, token)
        return record is not None and record.stage == sessions.ACTIVE
    finally:
        db.close()


@router.websocket("/stream")
async def stream(websocket: WebSocket) -> None:
    """Realtime notifications. Authenticated with the session cookie; the Origin header must
    match an allowed origin to prevent cross-site WebSocket hijacking."""
    settings = get_settings()
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host", "")
    allowed = set(settings.cors_origins) | {f"http://{host}", f"https://{host}"}
    if origin and origin not in allowed:
        await websocket.close(code=4403)
        return
    token = websocket.cookies.get(settings.session_cookie_name)
    if not token or not await asyncio.to_thread(_session_alive, token):
        await websocket.close(code=4401)
        return
    await websocket.accept()
    queue = hub.subscribe()
    try:
        await websocket.send_json({"type": "hello", "server_time": utcnow().isoformat()})
        while True:
            try:
                message = await asyncio.wait_for(queue.get(), timeout=25)
            except TimeoutError:
                # Re-validate periodically so revoked or expired sessions are disconnected.
                if not await asyncio.to_thread(_session_alive, token):
                    await websocket.close(code=4401)
                    return
                message = {"type": "ping"}
            await websocket.send_json(message)
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        hub.unsubscribe(queue)
        with contextlib.suppress(RuntimeError):
            await websocket.close()
