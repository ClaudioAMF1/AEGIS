"""Retention: delete telemetry older than the configured window.

Events referenced by alerts or incidents are evidence and are kept. Login-attempt records used
for throttling are trimmed after a day.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from aegis.config import get_settings
from aegis.db import utcnow
from aegis.models import AlertEvent, Event, IncidentEvent, LoginAttempt


def purge(db: Session, days: int | None = None) -> dict[str, int]:
    window = days or get_settings().event_retention_days
    cutoff = utcnow() - timedelta(days=window)
    protected = select(AlertEvent.event_id).union(select(IncidentEvent.event_id))
    events = db.execute(delete(Event).where(Event.occurred_at < cutoff, Event.id.not_in(protected)))
    attempts = db.execute(
        delete(LoginAttempt).where(LoginAttempt.attempted_at < utcnow() - timedelta(days=1))
    )
    db.commit()
    return {
        "events": int(getattr(events, "rowcount", 0) or 0),
        "login_attempts": int(getattr(attempts, "rowcount", 0) or 0),
        "retention_days": window,
    }
