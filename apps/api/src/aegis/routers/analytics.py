"""Dashboard overview and analytics."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select

from aegis.config import PipelineMode, get_settings
from aegis.db import utcnow
from aegis.events.broker import BrokerUnavailable, StreamBroker
from aegis.models import Alert, Event, Incident
from aegis.routers.common import scope_clause
from aegis.schemas import Scope
from aegis.security.deps import DbSession, Principal, require
from aegis.security.rbac import Permission
from aegis.services import analytics as svc

router = APIRouter(tags=["analytics"])
Reader = Annotated[Principal, Depends(require(Permission.TELEMETRY_READ))]


def _period(hours: int, start: datetime | None, end: datetime | None) -> tuple[datetime, datetime]:
    end = end or utcnow()
    start = start or end - timedelta(hours=hours)
    if start >= end:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "start must precede end")
    return start, end


@router.get("/dashboard")
def dashboard(
    _: Reader,
    db: DbSession,
    scope: Scope = Scope.LIVE,
    hours: Annotated[int, Query(ge=1, le=720)] = 24,
) -> dict[str, Any]:
    start, end = _period(hours, None, None)
    data = svc.overview(db, scope, start, end)
    recent_alerts = db.scalars(
        select(Alert)
        .where(scope_clause(Alert.is_synthetic, scope))
        .order_by(Alert.created_at.desc())
        .limit(8)
    ).all()
    recent_incidents = db.scalars(
        select(Incident)
        .where(scope_clause(Incident.is_synthetic, scope))
        .order_by(Incident.updated_at.desc())
        .limit(5)
    ).all()
    recent_events = db.scalars(
        select(Event)
        .where(scope_clause(Event.is_synthetic, scope))
        .order_by(Event.ingested_at.desc())
        .limit(12)
    ).all()
    settings = get_settings()
    pipeline: dict[str, Any] = {
        "mode": settings.pipeline_mode.value,
        "backlog": None,
        "healthy": True,
    }
    if settings.pipeline_mode == PipelineMode.BROKER:
        try:
            pipeline["backlog"] = StreamBroker().backlog()
        except BrokerUnavailable:
            pipeline["healthy"] = False
    data.update(
        {
            "pipeline": pipeline,
            "recent_alerts": [
                {
                    "id": str(a.id),
                    "title": a.title,
                    "severity": a.severity,
                    "status": a.status,
                    "created_at": a.created_at,
                    "hit_count": a.hit_count,
                    "incident_id": a.incident_id,
                }
                for a in recent_alerts
            ],
            "recent_incidents": [
                {
                    "id": str(i.id),
                    "number": i.number,
                    "title": i.title,
                    "severity": i.severity,
                    "status": i.status,
                    "updated_at": i.updated_at,
                }
                for i in recent_incidents
            ],
            "recent_events": [
                {
                    "id": str(e.id),
                    "occurred_at": e.occurred_at,
                    "category": e.category,
                    "action": e.action,
                    "hostname": e.hostname,
                    "summary": e.summary,
                }
                for e in recent_events
            ],
        }
    )
    return data


@router.get("/analytics")
def analytics(
    _: Reader,
    db: DbSession,
    scope: Scope = Scope.LIVE,
    hours: Annotated[int, Query(ge=1, le=2160)] = 168,
    start: datetime | None = None,
    end: datetime | None = None,
) -> dict[str, Any]:
    period_start, period_end = _period(hours, start, end)
    return svc.analytics(db, scope, period_start, period_end)
