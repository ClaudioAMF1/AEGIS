"""Reports: generated from persisted data, stored as JSON, exported as JSON or PDF."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import select

from aegis.db import utcnow
from aegis.models import Report
from aegis.routers.common import not_found
from aegis.schemas import ORM, Scope
from aegis.security.deps import DbSession, Principal, client_ip, require
from aegis.security.rbac import Permission
from aegis.services import audit
from aegis.services import reports as svc

router = APIRouter(prefix="/reports", tags=["reports"])
Reader = Annotated[Principal, Depends(require(Permission.REPORTS_READ))]
Creator = Annotated[Principal, Depends(require(Permission.REPORTS_CREATE))]


class ReportOut(ORM):
    id: uuid.UUID
    title: str
    kind: str
    period_start: datetime
    period_end: datetime
    incident_id: uuid.UUID | None
    include_synthetic: bool
    created_by: uuid.UUID
    created_at: datetime


class ReportIn(BaseModel):
    kind: Annotated[str, Field(pattern="^(overview|incident)$")]
    title: Annotated[str, Field(min_length=3, max_length=255)] | None = None
    scope: Scope = Scope.LIVE
    start: AwareDatetime | None = None
    end: AwareDatetime | None = None
    incident_id: uuid.UUID | None = None


@router.post("", response_model=ReportOut, status_code=status.HTTP_201_CREATED)
def create_report(body: ReportIn, principal: Creator, request: Request, db: DbSession) -> ReportOut:
    if body.kind == "incident":
        if body.incident_id is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "incident_id required")
        try:
            content = svc.build_incident(db, body.incident_id)
        except KeyError as exc:
            raise not_found("incident") from exc
        title = body.title or f"Relatório do incidente INC-{content['incident']['number']:04d}"
    else:
        end = body.end or utcnow()
        start = body.start or end - timedelta(days=7)
        if start >= end:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "start must precede end")
        content = svc.build_overview(db, body.scope, start, end)
        title = body.title or f"Visão geral de segurança ({body.scope.value})"
    report = svc.create(
        db, title=title, content=content, user_id=principal.id, incident_id=body.incident_id
    )
    audit.record(
        db,
        action="report.create",
        resource_type="report",
        resource_id=report.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"kind": body.kind},
    )
    db.commit()
    return ReportOut.model_validate(report)


@router.get("", response_model=list[ReportOut])
def list_reports(_: Reader, db: DbSession) -> list[ReportOut]:
    rows = db.scalars(select(Report).order_by(Report.created_at.desc()).limit(200)).all()
    return [ReportOut.model_validate(r) for r in rows]


@router.get("/{report_id}.json")
def report_json(report_id: uuid.UUID, _: Reader, db: DbSession) -> dict[str, Any]:
    report = db.get(Report, report_id)
    if report is None:
        raise not_found("report")
    return {"id": str(report.id), "title": report.title, **report.content}


@router.get("/{report_id}.pdf")
def report_pdf(report_id: uuid.UUID, _: Reader, db: DbSession) -> Response:
    report = db.get(Report, report_id)
    if report is None:
        raise not_found("report")
    return Response(
        svc.render_pdf(report),
        media_type="application/pdf",
        headers={"content-disposition": f'attachment; filename="aegis-report-{report.id}.pdf"'},
    )
