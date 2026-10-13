"""Alert lifecycle: deduplication/suppression and grouping of related alerts into incidents."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from aegis.config import get_settings
from aegis.db import utcnow
from aegis.detection.sigma import RuleMeta
from aegis.models import (
    Alert,
    AlertEvent,
    AlertStatus,
    Event,
    Incident,
    IncidentEvent,
    IncidentStatus,
    Investigation,
    Severity,
)
from aegis.observability import metrics

_OPEN_INCIDENT = (IncidentStatus.NEW.value, IncidentStatus.INVESTIGATING.value)


@dataclass
class AlertOutcome:
    alert: Alert
    created: bool
    incident_id: uuid.UUID | None


def next_incident_number(db: Session) -> int:
    return int(db.scalar(select(func.coalesce(func.max(Incident.number), 0))) or 0) + 1


def _merge(values: list[str], extra: list[str]) -> list[str]:
    return sorted(set(values) | set(extra))


class AlertManager:
    def upsert(
        self,
        db: Session,
        *,
        rule_id: str,
        rule_version: int,
        meta: RuleMeta,
        endpoint_id: uuid.UUID,
        events: list[Event],
        dedup_scope: str,
        context: dict[str, Any],
    ) -> AlertOutcome:
        settings = get_settings()
        synthetic = any(e.is_synthetic for e in events)
        dedup_key = f"{rule_id}:{dedup_scope}:{'demo' if synthetic else 'live'}"[:128]
        first = min(e.occurred_at for e in events)
        last = max(e.occurred_at for e in events)
        window = timedelta(minutes=settings.alert_suppression_minutes)

        alert = db.scalar(
            select(Alert)
            .where(Alert.dedup_key == dedup_key, Alert.status != AlertStatus.CLOSED.value)
            .order_by(Alert.last_event_at.desc())
            .limit(1)
        )
        created = False
        if alert is not None and (
            alert.last_event_at - window <= last and first <= alert.last_event_at + window
        ):
            known = set(
                db.scalars(select(AlertEvent.event_id).where(AlertEvent.alert_id == alert.id))
            )
            new_events = [e for e in events if e.id not in known]
            alert.hit_count += len(new_events)
            alert.first_event_at = min(alert.first_event_at, first)
            alert.last_event_at = max(alert.last_event_at, last)
            alert.context = {**alert.context, **context}
            for e in new_events:
                db.add(AlertEvent(alert_id=alert.id, event_id=e.id))
        else:
            alert = Alert(
                rule_id=rule_id,
                rule_version=rule_version,
                title=meta.title,
                severity=meta.level,
                endpoint_id=endpoint_id,
                dedup_key=dedup_key,
                hit_count=len(events),
                first_event_at=first,
                last_event_at=last,
                attack_techniques=meta.techniques,
                attack_tactics=meta.tactics,
                context=context,
                is_synthetic=synthetic,
            )
            db.add(alert)
            db.flush()
            for e in events:
                db.add(AlertEvent(alert_id=alert.id, event_id=e.id))
            created = True
            metrics.ALERTS_CREATED.labels(severity=meta.level).inc()
        db.flush()
        incident_id = self._group_into_incident(db, alert, events, created)
        return AlertOutcome(alert=alert, created=created, incident_id=incident_id)

    def _group_into_incident(
        self, db: Session, alert: Alert, events: list[Event], created: bool
    ) -> uuid.UUID | None:
        """Attach the alert to an open incident on the same endpoint within the grouping window.

        High/critical alerts open a new incident when none exists; lower severities only join
        an existing one, so the incident queue is not flooded by low-fidelity detections.
        """
        settings = get_settings()
        window = timedelta(minutes=settings.incident_grouping_minutes)
        incident: Incident | None = None
        if alert.incident_id is not None:
            incident = db.get(Incident, alert.incident_id)
        if incident is None:
            candidates = db.scalars(
                select(Incident).where(
                    Incident.status.in_(_OPEN_INCIDENT),
                    Incident.is_synthetic.is_(alert.is_synthetic),
                )
            ).all()
            for candidate in candidates:
                same_host = str(alert.endpoint_id) in candidate.endpoint_ids
                end = candidate.ended_at or candidate.started_at
                close_in_time = (
                    candidate.started_at - window <= alert.last_event_at
                    and alert.first_event_at <= end + window
                )
                if same_host and close_in_time:
                    incident = candidate
                    break
        severity = Severity(alert.severity)
        if incident is None:
            if severity.rank < Severity.HIGH.rank:
                return None
            incident = Incident(
                number=next_incident_number(db),
                title=f"{alert.title} on {alert.endpoint.hostname if alert.endpoint else 'host'}",
                description="Opened automatically from a high-severity detection.",
                severity=alert.severity,
                started_at=alert.first_event_at,
                ended_at=alert.last_event_at,
                endpoint_ids=[str(alert.endpoint_id)],
                attack_techniques=list(alert.attack_techniques),
                attack_tactics=list(alert.attack_tactics),
                is_synthetic=alert.is_synthetic,
            )
            db.add(incident)
            db.flush()
            db.add(
                Investigation(
                    incident_id=incident.id,
                    entry_type="system",
                    author_name="AEGIS",
                    body=f"Incident opened by rule {alert.rule_id}.",
                    changes={"alert_id": str(alert.id)},
                )
            )
            metrics.INCIDENTS_CREATED.inc()
        else:
            if Severity(incident.severity).rank < severity.rank:
                incident.severity = alert.severity
            incident.started_at = min(incident.started_at, alert.first_event_at)
            incident.ended_at = max(incident.ended_at or alert.last_event_at, alert.last_event_at)
            incident.attack_techniques = _merge(incident.attack_techniques, alert.attack_techniques)
            incident.attack_tactics = _merge(incident.attack_tactics, alert.attack_tactics)
            if str(alert.endpoint_id) not in incident.endpoint_ids:
                incident.endpoint_ids = [*incident.endpoint_ids, str(alert.endpoint_id)]
            incident.updated_at = utcnow()
            if alert.incident_id is None:
                db.add(
                    Investigation(
                        incident_id=incident.id,
                        entry_type="system",
                        author_name="AEGIS",
                        body=f"Related alert '{alert.title}' grouped into incident.",
                        changes={"alert_id": str(alert.id)},
                    )
                )
        alert.incident_id = incident.id
        linked = set(
            db.scalars(
                select(IncidentEvent.event_id).where(IncidentEvent.incident_id == incident.id)
            )
        )
        for e in events:
            if e.id not in linked:
                db.add(IncidentEvent(incident_id=incident.id, event_id=e.id))
                linked.add(e.id)
        db.flush()
        return incident.id
