"""AI analyst endpoints. Advisory only: nothing returned here is ever executed."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from starlette.concurrency import run_in_threadpool

from aegis.config import get_settings
from aegis.models import AssistantQuery
from aegis.security.deps import DbSession, Principal, client_ip, require
from aegis.security.rbac import Permission
from aegis.services import assistant as svc
from aegis.services import audit

router = APIRouter(prefix="/assistant", tags=["assistant"])
User = Annotated[Principal, Depends(require(Permission.ASSISTANT_USE))]


class AskIn(BaseModel):
    task: svc.Task = "summarize"
    question: Annotated[str, Field(max_length=2000)] = ""
    incident_id: uuid.UUID | None = None
    alert_id: uuid.UUID | None = None


class AskOut(BaseModel):
    id: uuid.UUID
    engine: str
    answer: svc.AnalystAnswer
    evidence_ids: list[str]
    prompt_injection_flags: list[str]
    grounding: dict[str, int]
    knowledge_sources: list[str]
    latency_ms: float
    notice: str | None
    created_at: datetime


@router.get("/status")
def assistant_status(_: User) -> dict[str, Any]:
    settings = get_settings()
    configured = settings.anthropic_api_key is not None
    return {
        "llm_configured": configured,
        "model": settings.assistant_model if configured else None,
        "engine": f"anthropic:{settings.assistant_model}" if configured else "local-rules",
        "tasks": list(svc.TASK_PROMPTS),
    }


@router.post("/ask", response_model=AskOut)
async def ask(body: AskIn, principal: User, request: Request, db: DbSession) -> AskOut:
    try:
        result = await run_in_threadpool(
            svc.ask,
            db,
            task=body.task,
            question=body.question,
            incident_id=body.incident_id,
            alert_id=body.alert_id,
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{exc} not found") from exc
    record = AssistantQuery(
        user_id=principal.id,
        incident_id=body.incident_id,
        task=body.task,
        question=body.question,
        engine=result.engine,
        response={
            "answer": result.answer.model_dump(),
            "grounding": result.grounding,
            "prompt_injection_flags": result.suspicious,
            "knowledge_sources": result.knowledge_sources,
            "notice": result.notice,
            "alert_id": str(body.alert_id) if body.alert_id else None,
        },
        evidence_ids=result.evidence_ids,
        latency_ms=result.latency_ms,
    )
    db.add(record)
    audit.record(
        db,
        action="assistant.ask",
        resource_type="incident" if body.incident_id else "alert",
        resource_id=body.incident_id or body.alert_id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"task": body.task, "engine": result.engine},
    )
    db.commit()
    return AskOut(
        id=record.id,
        engine=result.engine,
        answer=result.answer,
        evidence_ids=result.evidence_ids,
        prompt_injection_flags=result.suspicious,
        grounding=result.grounding,
        knowledge_sources=result.knowledge_sources,
        latency_ms=result.latency_ms,
        notice=result.notice,
        created_at=record.created_at,
    )


@router.get("/history")
def history(
    principal: User, db: DbSession, incident_id: uuid.UUID | None = None
) -> list[dict[str, Any]]:
    """Each analyst sees their own query history."""
    stmt = (
        select(AssistantQuery)
        .where(AssistantQuery.user_id == principal.id)
        .order_by(AssistantQuery.created_at.desc())
        .limit(50)
    )
    if incident_id:
        stmt = stmt.where(AssistantQuery.incident_id == incident_id)
    return [
        {
            "id": str(q.id),
            "task": q.task,
            "question": q.question,
            "engine": q.engine,
            "incident_id": str(q.incident_id) if q.incident_id else None,
            "created_at": q.created_at,
            "latency_ms": q.latency_ms,
            **q.response,
        }
        for q in db.scalars(stmt)
    ]
