"""Threat intelligence: indicator management, bulk import and on-demand lookups."""

from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import AwareDatetime, BaseModel, Field
from sqlalchemy import func, or_, select

from aegis.db import utcnow
from aegis.models import Event, Severity, ThreatIndicator
from aegis.routers.common import not_found
from aegis.schemas import ORM, Page
from aegis.security.deps import DbSession, Principal, client_ip, require
from aegis.security.rbac import Permission
from aegis.services import audit, intel

router = APIRouter(prefix="/intel", tags=["intelligence"])
Reader = Annotated[Principal, Depends(require(Permission.INTEL_READ))]
Manager = Annotated[Principal, Depends(require(Permission.INTEL_MANAGE))]
Analyst = Annotated[Principal, Depends(require(Permission.ALERTS_TRIAGE))]


class IndicatorOut(ORM):
    id: uuid.UUID
    type: str
    value: str
    source: str
    confidence: int
    severity: str
    description: str
    tags: list[str]
    license: str | None
    first_seen_at: datetime
    last_seen_at: datetime
    expires_at: datetime | None
    hits: int
    is_synthetic: bool


class IndicatorIn(BaseModel):
    value: Annotated[str, Field(min_length=3, max_length=255)]
    source: Annotated[str, Field(min_length=2, max_length=64)] = "manual"
    confidence: Annotated[int, Field(ge=0, le=100)] = 50
    severity: Severity = Severity.MEDIUM
    description: Annotated[str, Field(max_length=2000)] = ""
    tags: list[Annotated[str, Field(max_length=32)]] = Field(default_factory=list, max_length=16)
    license: Annotated[str, Field(max_length=64)] | None = None
    expires_at: AwareDatetime | None = None


@router.get("/indicators", response_model=Page[IndicatorOut])
def list_indicators(
    _: Reader,
    db: DbSession,
    q: Annotated[str | None, Query(max_length=255)] = None,
    type_: Annotated[str | None, Query(alias="type", max_length=16)] = None,
    include_expired: bool = False,
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[IndicatorOut]:
    filters = []
    if q:
        filters.append(ThreatIndicator.value.contains(q.lower(), autoescape=True))
    if type_:
        filters.append(ThreatIndicator.type == type_)
    if not include_expired:
        filters.append(
            or_(ThreatIndicator.expires_at.is_(None), ThreatIndicator.expires_at > utcnow())
        )
    total = db.scalar(select(func.count()).select_from(ThreatIndicator).where(*filters))
    rows = db.scalars(
        select(ThreatIndicator)
        .where(*filters)
        .order_by(ThreatIndicator.hits.desc(), ThreatIndicator.last_seen_at.desc())
        .offset(offset)
        .limit(limit)
    ).all()
    return Page(items=[IndicatorOut.model_validate(r) for r in rows], total=total)


def _upsert(db: DbSession, body: IndicatorIn) -> tuple[ThreatIndicator, bool]:
    value = body.value.strip().lower()
    kind = intel.classify(value)
    if kind is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT,
            f"'{body.value}' is not an IP, CIDR, domain or SHA-256",
        )
    existing = db.scalar(
        select(ThreatIndicator).where(
            ThreatIndicator.type == kind,
            ThreatIndicator.value == value,
            ThreatIndicator.source == body.source,
        )
    )
    if existing is not None:
        existing.confidence = body.confidence
        existing.severity = body.severity.value
        existing.description = body.description
        existing.tags = body.tags
        existing.expires_at = body.expires_at
        existing.last_seen_at = utcnow()
        return existing, False
    indicator = ThreatIndicator(
        type=kind,
        value=value,
        source=body.source,
        confidence=body.confidence,
        severity=body.severity.value,
        description=body.description,
        tags=body.tags,
        license=body.license,
        expires_at=body.expires_at,
    )
    db.add(indicator)
    return indicator, True


@router.post("/indicators", response_model=IndicatorOut, status_code=status.HTTP_201_CREATED)
def create_indicator(
    body: IndicatorIn, principal: Manager, request: Request, db: DbSession
) -> IndicatorOut:
    indicator, created = _upsert(db, body)
    db.flush()
    audit.record(
        db,
        action="intel.indicator_upsert",
        resource_type="indicator",
        resource_id=indicator.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"value": indicator.value, "created": created},
    )
    db.commit()
    return IndicatorOut.model_validate(indicator)


@router.delete("/indicators/{indicator_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_indicator(
    indicator_id: uuid.UUID, principal: Manager, request: Request, db: DbSession
) -> None:
    indicator = db.get(ThreatIndicator, indicator_id)
    if indicator is None:
        raise not_found("indicator")
    audit.record(
        db,
        action="intel.indicator_delete",
        resource_type="indicator",
        resource_id=indicator.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"value": indicator.value},
    )
    db.delete(indicator)
    db.commit()


class ImportIn(BaseModel):
    csv: Annotated[str, Field(max_length=2_000_000)]
    source: Annotated[str, Field(min_length=2, max_length=64)]
    license: Annotated[str, Field(max_length=64)] | None = None
    default_confidence: Annotated[int, Field(ge=0, le=100)] = 50


class ImportOut(BaseModel):
    created: int
    updated: int
    rejected: list[str]


@router.post("/indicators/import", response_model=ImportOut)
def import_indicators(
    body: ImportIn, principal: Manager, request: Request, db: DbSession
) -> ImportOut:
    """Import a CSV with columns ``value[,severity,confidence,description]``. Lines starting
    with ``#`` are ignored. Values are classified automatically; unknown shapes are rejected."""
    created = updated = 0
    rejected: list[str] = []
    reader = csv.reader(io.StringIO(body.csv))
    for line_no, row in enumerate(reader, start=1):
        if not row or row[0].strip().startswith("#") or row[0].strip().lower() == "value":
            continue
        if line_no > 20_000:
            rejected.append("import truncated at 20000 lines")
            break
        try:
            severity = (
                Severity(row[1].strip().lower())
                if len(row) > 1 and row[1].strip()
                else (Severity.MEDIUM)
            )
            confidence = (
                int(row[2]) if len(row) > 2 and row[2].strip() else (body.default_confidence)
            )
            item = IndicatorIn(
                value=row[0],
                source=body.source,
                license=body.license,
                severity=severity,
                confidence=max(0, min(100, confidence)),
                description=row[3][:2000] if len(row) > 3 else "",
            )
            _, is_new = _upsert(db, item)
        except (ValueError, HTTPException) as exc:
            detail = exc.detail if isinstance(exc, HTTPException) else str(exc).split("\n")[0]
            rejected.append(f"line {line_no}: {detail}"[:200])
            continue
        created += int(is_new)
        updated += int(not is_new)
        db.flush()
    audit.record(
        db,
        action="intel.import",
        resource_type="indicator",
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"source": body.source, "created": created, "updated": updated},
    )
    db.commit()
    return ImportOut(created=created, updated=updated, rejected=rejected[:100])


class LookupOut(BaseModel):
    value: str
    type: str | None
    local_matches: list[IndicatorOut]
    sightings: int
    last_seen: datetime | None
    external: dict[str, object] | None
    note: str = (
        "Threat intelligence is an auxiliary signal. A match is not proof of compromise; "
        "confirm with telemetry and context."
    )


@router.get("/lookup", response_model=LookupOut)
def lookup(
    _: Analyst, db: DbSession, value: Annotated[str, Query(min_length=3, max_length=255)]
) -> LookupOut:
    value = value.strip().lower()
    kind = intel.classify(value)
    matches = db.scalars(select(ThreatIndicator).where(ThreatIndicator.value == value)).all()
    sighting_filter = or_(Event.src_ip == value, Event.dst_ip == value)
    sightings = db.scalar(select(func.count()).select_from(Event).where(sighting_filter)) or 0
    last_seen = db.scalar(select(func.max(Event.occurred_at)).where(sighting_filter))
    external = None
    if kind in {"ipv4", "ipv6"}:
        result = intel.lookup_ip(db, value)
        external = result.__dict__
    return LookupOut(
        value=value,
        type=kind,
        local_matches=[IndicatorOut.model_validate(m) for m in matches],
        sightings=sightings,
        last_seen=last_seen,
        external=external,
    )


@router.get("/summary")
def summary(_: Reader, db: DbSession) -> dict[str, object]:
    by_type = dict(
        db.execute(select(ThreatIndicator.type, func.count()).group_by(ThreatIndicator.type)).all()
    )
    by_source = dict(
        db.execute(
            select(ThreatIndicator.source, func.count()).group_by(ThreatIndicator.source)
        ).all()
    )
    top = db.scalars(
        select(ThreatIndicator)
        .where(ThreatIndicator.hits > 0)
        .order_by(ThreatIndicator.hits.desc())
        .limit(10)
    ).all()
    return {
        "by_type": by_type,
        "by_source": by_source,
        "top_hits": [IndicatorOut.model_validate(t).model_dump(mode="json") for t in top],
    }
