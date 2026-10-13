"""Server-side sessions with idle and absolute expiry, rotation and revocation."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from aegis.config import get_settings
from aegis.db import utcnow
from aegis.models import AuthSession, User
from aegis.security.crypto import hash_token, new_token

MFA_PENDING = "mfa_pending"
ACTIVE = "active"
_MFA_PENDING_TTL = timedelta(minutes=5)


@dataclass(frozen=True)
class IssuedSession:
    token: str
    session: AuthSession


def issue(
    db: Session,
    user: User,
    *,
    stage: str = ACTIVE,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> IssuedSession:
    settings = get_settings()
    token = new_token("aes_")
    now = utcnow()
    ttl = (
        _MFA_PENDING_TTL
        if stage == MFA_PENDING
        else timedelta(hours=settings.session_absolute_hours)
    )
    record = AuthSession(
        user_id=user.id,
        token_hash=hash_token(token),
        csrf_token=secrets.token_urlsafe(24),
        stage=stage,
        created_at=now,
        last_seen_at=now,
        expires_at=now + ttl,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:255] or None,
    )
    db.add(record)
    db.flush()
    return IssuedSession(token=token, session=record)


def resolve(db: Session, token: str) -> AuthSession | None:
    """Return a live session for ``token`` and slide its idle timer, or ``None``."""
    settings = get_settings()
    record = db.scalar(select(AuthSession).where(AuthSession.token_hash == hash_token(token)))
    if record is None or record.revoked_at is not None:
        return None
    now = utcnow()
    if now >= record.expires_at:
        return None
    idle_limit = timedelta(minutes=settings.session_idle_minutes)
    if record.stage == ACTIVE and now - record.last_seen_at > idle_limit:
        record.revoked_at = now
        db.commit()
        return None
    if not record.user.is_active:
        return None
    # Avoid a write on every request: only persist when the timer moved meaningfully.
    if now - record.last_seen_at > timedelta(seconds=30):
        record.last_seen_at = now
        db.commit()
    return record


def revoke(db: Session, record: AuthSession) -> None:
    record.revoked_at = utcnow()


def revoke_all_for_user(db: Session, user_id: object, *, except_id: object = None) -> int:
    stmt = (
        update(AuthSession)
        .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    if except_id is not None:
        stmt = stmt.where(AuthSession.id != except_id)
    result = db.execute(stmt)
    return int(getattr(result, "rowcount", 0) or 0)
