"""Authentication: password login, TOTP MFA, sessions and account self-service."""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select

from aegis.config import get_settings
from aegis.db import utcnow
from aegis.models import AuthSession, LoginAttempt, User
from aegis.security import sessions, totp
from aegis.security.crypto import (
    EMAIL_PATTERN,
    decrypt_field,
    encrypt_field,
    hash_password,
    needs_rehash,
    password_problems,
    verify_password,
)
from aegis.security.deps import (
    CurrentPrincipal,
    DbSession,
    Principal,
    client_ip,
    mfa_pending_principal,
)
from aegis.services import audit

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginIn(BaseModel):
    email: Annotated[str, Field(pattern=EMAIL_PATTERN, max_length=320)]
    password: Annotated[str, Field(min_length=1, max_length=256)]


class MfaCodeIn(BaseModel):
    code: Annotated[str, Field(min_length=6, max_length=8)]


class PasswordChangeIn(BaseModel):
    current_password: Annotated[str, Field(max_length=256)]
    new_password: Annotated[str, Field(max_length=256)]


class MeOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    role: str
    permissions: list[str]
    mfa_enabled: bool
    csrf_token: str
    session_expires_at: datetime


class LoginOut(BaseModel):
    mfa_required: bool
    csrf_token: str
    user: MeOut | None = None


class SessionOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    expires_at: datetime
    ip_address: str | None
    user_agent: str | None
    current: bool


def _me(principal: Principal) -> MeOut:
    return MeOut(
        id=principal.user.id,
        email=principal.user.email,
        display_name=principal.user.display_name,
        role=principal.user.role,
        permissions=sorted(p.value for p in principal.permissions),
        mfa_enabled=principal.user.mfa_enabled,
        csrf_token=principal.session.csrf_token,
        session_expires_at=principal.session.expires_at,
    )


def _set_cookie(response: Response, token: str, expires_at: datetime) -> None:
    settings = get_settings()
    response.set_cookie(
        settings.session_cookie_name,
        token,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="lax",
        expires=expires_at,
        path="/",
    )


def _throttled(db: DbSession, keys: list[str]) -> bool:
    settings = get_settings()
    since = utcnow() - timedelta(seconds=settings.login_window_seconds)
    for key in keys:
        count = db.scalar(
            select(func.count())
            .select_from(LoginAttempt)
            .where(LoginAttempt.key == key, LoginAttempt.attempted_at >= since)
        )
        limit = settings.login_max_attempts * (4 if key.startswith("ip:") else 1)
        if (count or 0) >= limit:
            return True
    return False


@router.post("/login", response_model=LoginOut)
def login(body: LoginIn, request: Request, response: Response, db: DbSession) -> LoginOut:
    settings = get_settings()
    email = body.email.lower()
    ip = client_ip(request)
    keys = [f"user:{email}", f"ip:{ip}"]
    invalid = HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid credentials")

    if _throttled(db, keys):
        audit.record(
            db,
            action="auth.login",
            resource_type="user",
            actor_email=email,
            outcome="throttled",
            ip_address=ip,
        )
        db.commit()
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            "too many attempts, try later",
            headers={"Retry-After": str(settings.login_window_seconds)},
        )

    user = db.scalar(select(User).where(User.email == email))
    password_ok = verify_password(user.password_hash if user else None, body.password)
    now = utcnow()
    locked = user is not None and user.locked_until is not None and user.locked_until > now

    if user is None or not password_ok or not user.is_active or locked:
        for key in keys:
            db.add(LoginAttempt(key=key, attempted_at=now))
        if user is not None and not locked:
            user.failed_login_count += 1
            if user.failed_login_count >= settings.login_max_attempts:
                user.locked_until = now + timedelta(minutes=settings.lockout_minutes)
                user.failed_login_count = 0
        audit.record(
            db,
            action="auth.login",
            resource_type="user",
            resource_id=user.id if user else None,
            actor_email=email,
            outcome="locked" if locked else "failure",
            ip_address=ip,
        )
        db.commit()
        raise invalid

    if needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)
    user.failed_login_count = 0
    user.locked_until = None
    db.execute(delete(LoginAttempt).where(LoginAttempt.key == f"user:{email}"))

    # Session fixation defence: an existing cookie is never upgraded, a new session is issued.
    stage = sessions.MFA_PENDING if user.mfa_enabled else sessions.ACTIVE
    issued = sessions.issue(
        db, user, stage=stage, ip_address=ip, user_agent=request.headers.get("user-agent")
    )
    if stage == sessions.ACTIVE:
        user.last_login_at = now
    audit.record(
        db,
        action="auth.login",
        resource_type="user",
        resource_id=user.id,
        actor_id=user.id,
        actor_email=user.email,
        ip_address=ip,
        details={"mfa_pending": stage == sessions.MFA_PENDING},
    )
    db.commit()
    _set_cookie(response, issued.token, issued.session.expires_at)
    if stage == sessions.MFA_PENDING:
        return LoginOut(mfa_required=True, csrf_token=issued.session.csrf_token)
    principal = Principal(user=user, session=issued.session, via_cookie=True)
    return LoginOut(mfa_required=False, csrf_token=issued.session.csrf_token, user=_me(principal))


@router.post("/mfa/verify", response_model=LoginOut)
def verify_mfa(
    body: MfaCodeIn,
    request: Request,
    response: Response,
    db: DbSession,
    pending: Annotated[Principal, Depends(mfa_pending_principal)],
) -> LoginOut:
    user = pending.user
    ip = client_ip(request)
    if _throttled(db, [f"mfa:{user.id}"]):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "too many attempts, try later")
    secret = decrypt_field(user.mfa_secret_encrypted or "")
    step = totp.verify(secret, body.code, user.mfa_last_used_step) if secret else None
    if step is None:
        db.add(LoginAttempt(key=f"mfa:{user.id}"))
        audit.record(
            db,
            action="auth.mfa_verify",
            resource_type="user",
            resource_id=user.id,
            actor_id=user.id,
            actor_email=user.email,
            outcome="failure",
            ip_address=ip,
        )
        db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid code")
    user.mfa_last_used_step = step
    user.last_login_at = utcnow()
    sessions.revoke(db, pending.session)  # rotate: the pending token can never become active
    issued = sessions.issue(db, user, ip_address=ip, user_agent=request.headers.get("user-agent"))
    audit.record(
        db,
        action="auth.mfa_verify",
        resource_type="user",
        resource_id=user.id,
        actor_id=user.id,
        actor_email=user.email,
        ip_address=ip,
    )
    db.commit()
    _set_cookie(response, issued.token, issued.session.expires_at)
    principal = Principal(user=user, session=issued.session, via_cookie=True)
    return LoginOut(mfa_required=False, csrf_token=issued.session.csrf_token, user=_me(principal))


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    principal: CurrentPrincipal, request: Request, response: Response, db: DbSession
) -> None:
    sessions.revoke(db, principal.session)
    audit.record(
        db,
        action="auth.logout",
        resource_type="session",
        resource_id=principal.session.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
    )
    db.commit()
    response.delete_cookie(get_settings().session_cookie_name, path="/")


@router.get("/me", response_model=MeOut)
def me(principal: CurrentPrincipal) -> MeOut:
    return _me(principal)


@router.get("/sessions", response_model=list[SessionOut])
def list_sessions(principal: CurrentPrincipal, db: DbSession) -> list[SessionOut]:
    rows = db.scalars(
        select(AuthSession)
        .where(
            AuthSession.user_id == principal.id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > utcnow(),
            AuthSession.stage == sessions.ACTIVE,
        )
        .order_by(AuthSession.last_seen_at.desc())
    ).all()
    return [
        SessionOut(
            id=r.id,
            created_at=r.created_at,
            last_seen_at=r.last_seen_at,
            expires_at=r.expires_at,
            ip_address=r.ip_address,
            user_agent=r.user_agent,
            current=r.id == principal.session.id,
        )
        for r in rows
    ]


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_session(
    session_id: uuid.UUID, principal: CurrentPrincipal, request: Request, db: DbSession
) -> None:
    record = db.get(AuthSession, session_id)
    if record is None or record.user_id != principal.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    sessions.revoke(db, record)
    audit.record(
        db,
        action="auth.session_revoke",
        resource_type="session",
        resource_id=record.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
    )
    db.commit()


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    body: PasswordChangeIn, principal: CurrentPrincipal, request: Request, db: DbSession
) -> None:
    user = principal.user
    if not verify_password(user.password_hash, body.current_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "current password is incorrect")
    problems = password_problems(body.new_password, user.email)
    if problems:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "password " + "; ".join(problems)
        )
    user.password_hash = hash_password(body.new_password)
    revoked = sessions.revoke_all_for_user(db, user.id, except_id=principal.session.id)
    audit.record(
        db,
        action="auth.password_change",
        resource_type="user",
        resource_id=user.id,
        actor_id=user.id,
        actor_email=user.email,
        ip_address=client_ip(request),
        details={"other_sessions_revoked": revoked},
    )
    db.commit()


class MfaSetupOut(BaseModel):
    secret: str
    otpauth_uri: str


@router.post("/mfa/setup", response_model=MfaSetupOut)
def mfa_setup(principal: CurrentPrincipal, db: DbSession) -> MfaSetupOut:
    user = principal.user
    if user.mfa_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "MFA is already enabled")
    secret = totp.new_secret()
    user.mfa_secret_encrypted = encrypt_field(secret)
    db.commit()
    return MfaSetupOut(secret=secret, otpauth_uri=totp.provisioning_uri(secret, user.email))


@router.post("/mfa/enable", status_code=status.HTTP_204_NO_CONTENT)
def mfa_enable(
    body: MfaCodeIn, principal: CurrentPrincipal, request: Request, db: DbSession
) -> None:
    user = principal.user
    secret = decrypt_field(user.mfa_secret_encrypted or "")
    step = totp.verify(secret, body.code, None) if secret else None
    if step is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid code")
    user.mfa_enabled = True
    user.mfa_last_used_step = step
    revoked = sessions.revoke_all_for_user(db, user.id, except_id=principal.session.id)
    audit.record(
        db,
        action="auth.mfa_enable",
        resource_type="user",
        resource_id=user.id,
        actor_id=user.id,
        actor_email=user.email,
        ip_address=client_ip(request),
        details={"other_sessions_revoked": revoked},
    )
    db.commit()


class MfaDisableIn(BaseModel):
    password: Annotated[str, Field(max_length=256)]
    code: Annotated[str, Field(min_length=6, max_length=8)]


@router.post("/mfa/disable", status_code=status.HTTP_204_NO_CONTENT)
def mfa_disable(
    body: MfaDisableIn, principal: CurrentPrincipal, request: Request, db: DbSession
) -> None:
    user = principal.user
    secret = decrypt_field(user.mfa_secret_encrypted or "")
    step = totp.verify(secret, body.code, user.mfa_last_used_step) if secret else None
    if not verify_password(user.password_hash, body.password) or step is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid password or code")
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    user.mfa_last_used_step = None
    audit.record(
        db,
        action="auth.mfa_disable",
        resource_type="user",
        resource_id=user.id,
        actor_id=user.id,
        actor_email=user.email,
        ip_address=client_ip(request),
    )
    db.commit()
