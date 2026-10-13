"""Detection rules: listing, versions, enable/disable, dry-run testing, execution history."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from aegis.db import utcnow
from aegis.detection.fields import flatten
from aegis.detection.registry import registry
from aegis.detection.sigma import CorrelationRuleDef, RuleError, compile_rule
from aegis.events.contract import EventIn
from aegis.models import DetectionRule, DetectionRun, Event
from aegis.routers.common import not_found, scope_clause
from aegis.schemas import EventOut, RuleDetail, RuleOut, Scope
from aegis.security.deps import DbSession, Principal, client_ip, require
from aegis.security.rbac import Permission
from aegis.services import audit

router = APIRouter(prefix="/detections", tags=["detections"])
Reader = Annotated[Principal, Depends(require(Permission.RULES_READ))]
Manager = Annotated[Principal, Depends(require(Permission.RULES_MANAGE))]


@router.get("/rules", response_model=list[RuleOut])
def list_rules(_: Reader, db: DbSession) -> list[RuleOut]:
    rows = db.scalars(
        select(DetectionRule)
        .where(DetectionRule.is_current.is_(True))
        .order_by(DetectionRule.title)
    ).all()
    return [RuleOut.model_validate(r) for r in rows]


@router.get("/rules/errors")
def rule_errors(_: Reader) -> list[dict[str, str]]:
    return [{"path": e.path, "error": e.error} for e in registry.load_errors]


@router.get("/rules/{rule_id}", response_model=RuleDetail)
def get_rule(rule_id: str, _: Reader, db: DbSession) -> RuleDetail:
    versions = db.scalars(
        select(DetectionRule)
        .where(DetectionRule.rule_id == rule_id)
        .order_by(DetectionRule.version.desc())
    ).all()
    current = next((v for v in versions if v.is_current), None)
    if current is None:
        raise not_found("rule")
    return RuleDetail.model_validate(current).model_copy(
        update={
            "versions": [
                {
                    "version": v.version,
                    "created_at": v.created_at,
                    "sha256": v.content_sha256,
                    "is_current": v.is_current,
                    "title": v.title,
                }
                for v in versions
            ]
        }
    )


class RulePatch(BaseModel):
    enabled: bool
    reason: Annotated[str, Field(min_length=3, max_length=500)]


@router.patch("/rules/{rule_id}", response_model=RuleOut)
def toggle_rule(
    rule_id: str, body: RulePatch, principal: Manager, request: Request, db: DbSession
) -> RuleOut:
    rule = db.scalar(
        select(DetectionRule).where(
            DetectionRule.rule_id == rule_id, DetectionRule.is_current.is_(True)
        )
    )
    if rule is None:
        raise not_found("rule")
    previous = rule.enabled
    rule.enabled = body.enabled
    rule.updated_at = utcnow()
    audit.record(
        db,
        action="rule.toggle",
        resource_type="rule",
        resource_id=rule_id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"enabled": body.enabled, "previous": previous, "reason": body.reason},
    )
    db.commit()
    registry.refresh(db, force=True)
    return RuleOut.model_validate(rule)


class RuleTestIn(BaseModel):
    content: Annotated[str, Field(max_length=50_000)] | None = None
    rule_id: str | None = None
    events: list[dict[str, Any]] | None = Field(default=None, max_length=200)
    scope: Scope = Scope.ALL
    hours: Annotated[int, Field(ge=1, le=720)] = 24
    limit: Annotated[int, Field(ge=1, le=20_000)] = 5000


class RuleTestOut(BaseModel):
    valid: bool
    error: str | None = None
    kind: str | None = None
    evaluated: int = 0
    matched: int = 0
    matches: list[EventOut] = []
    sample_results: list[bool] = []


@router.post("/test", response_model=RuleTestOut)
def test_rule(body: RuleTestIn, _: Reader, db: DbSession) -> RuleTestOut:
    """Dry-run a rule (stored or draft) against supplied events or recent telemetry.
    Nothing is persisted and no alerts are produced."""
    content = body.content
    if content is None and body.rule_id:
        stored = db.scalar(
            select(DetectionRule.content).where(
                DetectionRule.rule_id == body.rule_id, DetectionRule.is_current.is_(True)
            )
        )
        if stored is None:
            raise not_found("rule")
        content = stored
    if content is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, "content or rule_id required")
    try:
        definition = compile_rule(content)
    except RuleError as exc:
        return RuleTestOut(valid=False, error=str(exc))
    if isinstance(definition, CorrelationRuleDef):
        return RuleTestOut(
            valid=True,
            kind="correlation",
            error="correlation rules are evaluated over stored matches; "
            "use a demo scenario replay to exercise them",
        )
    if body.events is not None:
        results = []
        for raw in body.events:
            try:
                payload = EventIn.model_validate(raw).model_dump(mode="json", exclude_none=True)
            except ValueError:
                results.append(False)
                continue
            results.append(definition.matches(flatten(payload)))
        return RuleTestOut(
            valid=True,
            kind="sigma",
            evaluated=len(results),
            matched=sum(results),
            sample_results=results,
        )
    since = utcnow() - timedelta(hours=body.hours)
    events = db.scalars(
        select(Event)
        .where(
            scope_clause(Event.is_synthetic, body.scope),
            Event.occurred_at >= since,
            Event.category == definition.category,
        )
        .order_by(Event.occurred_at.desc())
        .limit(body.limit)
    ).all()
    matched = [e for e in events if definition.matches(flatten(e.payload, e.enrichment))]
    return RuleTestOut(
        valid=True,
        kind="sigma",
        evaluated=len(events),
        matched=len(matched),
        matches=[EventOut.model_validate(e) for e in matched[:100]],
    )


class RunOut(BaseModel):
    id: str
    started_at: datetime
    duration_ms: float
    trigger: str
    events_evaluated: int
    rules_evaluated: int
    matches: int
    alerts_created: int
    errors: list[str]


@router.get("/runs", response_model=list[RunOut])
def detection_runs(
    _: Reader, db: DbSession, limit: Annotated[int, Query(ge=1, le=500)] = 50
) -> list[RunOut]:
    rows = db.scalars(
        select(DetectionRun).order_by(DetectionRun.started_at.desc()).limit(limit)
    ).all()
    return [
        RunOut(
            id=str(r.id),
            started_at=r.started_at,
            duration_ms=r.duration_ms,
            trigger=r.trigger,
            events_evaluated=r.events_evaluated,
            rules_evaluated=r.rules_evaluated,
            matches=r.matches,
            alerts_created=r.alerts_created,
            errors=r.errors,
        )
        for r in rows
    ]


@router.post("/reload")
def reload_rules(principal: Manager, request: Request, db: DbSession) -> dict[str, Any]:
    stats = registry.bootstrap(db)
    audit.record(
        db,
        action="rule.reload",
        resource_type="rule",
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details=stats,
    )
    db.commit()
    return {**stats, "errors": len(registry.load_errors)}
