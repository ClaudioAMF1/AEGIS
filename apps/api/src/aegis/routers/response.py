"""Response actions: propose -> preview -> explicit approval -> execution -> (revert)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from aegis.db import utcnow
from aegis.models import Endpoint, ResponseAction, ResponseStatus
from aegis.routers.common import not_found
from aegis.schemas import ORM
from aegis.security.deps import CurrentAgent, DbSession, Principal, client_ip, require
from aegis.security.rbac import Permission
from aegis.services import audit
from aegis.services import response as svc

router = APIRouter(tags=["response"])
Reader = Annotated[Principal, Depends(require(Permission.TELEMETRY_READ))]
Requester = Annotated[Principal, Depends(require(Permission.RESPONSE_REQUEST))]
Approver = Annotated[Principal, Depends(require(Permission.RESPONSE_APPROVE))]


class ActionOut(ORM):
    id: uuid.UUID
    action_type: str
    target_type: str
    target_id: str
    incident_id: uuid.UUID | None
    status: str
    justification: str
    impact_preview: dict[str, Any]
    result: dict[str, Any]
    reversible: bool
    requested_by: uuid.UUID
    approved_by: uuid.UUID | None
    requested_at: datetime
    decided_at: datetime | None
    executed_at: datetime | None
    reverted_at: datetime | None


@router.get("/response/catalogue")
def catalogue(_: Reader) -> list[dict[str, object]]:
    return [
        {
            "action_type": k,
            "target_type": v.target_type,
            "description": v.description,
            "reversible": v.reversible,
            "server_side": v.server_side,
        }
        for k, v in svc.CATALOGUE.items()
    ]


class PreviewIn(BaseModel):
    action_type: Annotated[str, Field(max_length=48)]
    target_id: Annotated[str, Field(max_length=64)]
    parameters: dict[str, str] = Field(default_factory=dict)


@router.post("/response/preview")
def preview(body: PreviewIn, _: Requester, db: DbSession) -> dict[str, Any]:
    try:
        return svc.preview(db, body.action_type, body.target_id, body.parameters)
    except svc.ResponseError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc


class ProposeIn(PreviewIn):
    justification: Annotated[str, Field(min_length=10, max_length=4000)]
    incident_id: uuid.UUID | None = None


@router.post("/response/actions", response_model=ActionOut, status_code=status.HTTP_201_CREATED)
def propose(body: ProposeIn, principal: Requester, request: Request, db: DbSession) -> ActionOut:
    try:
        impact = svc.preview(db, body.action_type, body.target_id, body.parameters)
    except svc.ResponseError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    spec = svc.CATALOGUE[body.action_type]
    action = ResponseAction(
        action_type=body.action_type,
        target_type=spec.target_type,
        target_id=body.target_id,
        incident_id=body.incident_id,
        justification=body.justification,
        impact_preview={**impact, "parameters": body.parameters},
        reversible=spec.reversible,
        requested_by=principal.id,
    )
    db.add(action)
    db.flush()
    audit.record(
        db,
        action="response.propose",
        resource_type="response_action",
        resource_id=action.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"type": body.action_type, "target": impact["target_label"]},
    )
    db.commit()
    return ActionOut.model_validate(action)


@router.get("/response/actions", response_model=list[ActionOut])
def list_actions(
    _: Reader,
    db: DbSession,
    incident_id: uuid.UUID | None = None,
    status_: Annotated[str | None, Query(alias="status", max_length=16)] = None,
) -> list[ActionOut]:
    stmt = select(ResponseAction).order_by(ResponseAction.requested_at.desc()).limit(200)
    if incident_id:
        stmt = stmt.where(ResponseAction.incident_id == incident_id)
    if status_:
        stmt = stmt.where(ResponseAction.status == status_)
    return [ActionOut.model_validate(a) for a in db.scalars(stmt)]


class DecisionIn(BaseModel):
    approve: bool
    confirmation: Annotated[str, Field(max_length=255)] = ""
    comment: Annotated[str, Field(max_length=2000)] = ""


@router.post("/response/actions/{action_id}/decision", response_model=ActionOut)
def decide(
    action_id: uuid.UUID, body: DecisionIn, principal: Approver, request: Request, db: DbSession
) -> ActionOut:
    action = db.get(ResponseAction, action_id)
    if action is None:
        raise not_found("response action")
    if action.status != ResponseStatus.PROPOSED.value:
        raise HTTPException(status.HTTP_409_CONFLICT, f"action is already {action.status}")
    if action.requested_by == principal.id and body.approve and not svc.can_self_approve():
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "four-eyes rule: another administrator must approve this request",
        )
    if body.approve and body.confirmation != action.impact_preview.get("confirmation_text"):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "type the target name exactly to confirm"
        )
    action.decided_at = utcnow()
    action.approved_by = principal.id
    outcome = "rejected"
    if body.approve:
        action.status = ResponseStatus.APPROVED.value
        try:
            # Re-validate: state may have changed since the request was made.
            svc.preview(
                db,
                action.action_type,
                action.target_id,
                action.impact_preview.get("parameters", {}),
            )
            svc.execute(db, action, principal.user)
            outcome = action.status
        except svc.ResponseError as exc:
            action.status = ResponseStatus.FAILED.value
            action.result = {"error": str(exc)}
            outcome = "failed"
    else:
        action.status = ResponseStatus.REJECTED.value
    audit.record(
        db,
        action="response.decision",
        resource_type="response_action",
        resource_id=action.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        outcome=outcome,
        details={"type": action.action_type, "comment": body.comment[:500]},
    )
    db.commit()
    return ActionOut.model_validate(action)


@router.post("/response/actions/{action_id}/revert", response_model=ActionOut)
def revert(action_id: uuid.UUID, principal: Approver, request: Request, db: DbSession) -> ActionOut:
    action = db.get(ResponseAction, action_id)
    if action is None:
        raise not_found("response action")
    if not action.reversible or action.status != ResponseStatus.EXECUTED.value:
        raise HTTPException(status.HTTP_409_CONFLICT, "only executed reversible actions revert")
    try:
        svc.revert(db, action, principal.user)
    except svc.ResponseError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, str(exc)) from exc
    audit.record(
        db,
        action="response.revert",
        resource_type="response_action",
        resource_id=action.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"type": action.action_type},
    )
    db.commit()
    return ActionOut.model_validate(action)


class AgentResultIn(BaseModel):
    outcome: Annotated[str, Field(pattern="^(executed|failed|simulated)$")]
    detail: Annotated[str, Field(max_length=1000)] = ""


@router.post("/ingest/actions/{action_id}/result", response_model=ActionOut)
def agent_result(
    action_id: uuid.UUID, body: AgentResultIn, agent: CurrentAgent, db: DbSession
) -> ActionOut:
    """Agents acknowledge actions delivered on the heartbeat. Only the target's agent may."""
    action = db.get(ResponseAction, action_id)
    if (
        action is None
        or action.target_type != "endpoint"
        or (action.target_id != str(agent.endpoint_id))
    ):
        raise not_found("response action")
    if action.status != ResponseStatus.APPROVED.value:
        raise HTTPException(status.HTTP_409_CONFLICT, f"action is {action.status}")
    endpoint = db.get(Endpoint, agent.endpoint_id)
    action.status = (
        ResponseStatus.FAILED.value if body.outcome == "failed" else ResponseStatus.EXECUTED.value
    )
    action.executed_at = utcnow()
    action.result = {
        **action.result,
        "agent": str(agent.id),
        "outcome": body.outcome,
        "detail": body.detail,
    }
    if endpoint is not None and body.outcome != "failed":
        endpoint.isolation_state = (
            "isolated_simulated" if body.outcome == "simulated" else "isolated"
        )
    audit.record(
        db,
        action="response.agent_result",
        resource_type="response_action",
        resource_id=action.id,
        outcome=body.outcome,
        details={"agent": str(agent.id)},
    )
    db.commit()
    return ActionOut.model_validate(action)
