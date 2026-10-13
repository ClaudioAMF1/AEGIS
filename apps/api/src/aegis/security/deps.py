"""FastAPI dependencies for authentication, CSRF and authorisation."""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from aegis.config import get_settings
from aegis.db import get_db
from aegis.models import Agent, AgentStatus, AuthSession, User
from aegis.security import sessions
from aegis.security.crypto import constant_time_equals, hash_token
from aegis.security.rbac import Permission, has_permission, permissions_for

_SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

DbSession = Annotated[Session, Depends(get_db)]


@dataclass
class Principal:
    user: User
    session: AuthSession
    via_cookie: bool

    @property
    def id(self) -> uuid.UUID:
        return self.user.id

    @property
    def permissions(self) -> frozenset[Permission]:
        return permissions_for(self.user.role)

    def can(self, permission: Permission) -> bool:
        return has_permission(self.user.role, permission)


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _extract_token(request: Request) -> tuple[str | None, bool]:
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip(), False
    return request.cookies.get(get_settings().session_cookie_name), True


def _load_session(request: Request, db: Session, *, stage: str) -> Principal:
    token, via_cookie = _extract_token(request)
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "authentication required")
    if not token:
        raise unauthorized
    record = sessions.resolve(db, token)
    if record is None or record.stage != stage:
        raise unauthorized
    if via_cookie and request.method not in _SAFE_METHODS:
        sent = request.headers.get("x-csrf-token", "")
        if not sent or not constant_time_equals(sent, record.csrf_token):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "missing or invalid CSRF token")
    return Principal(user=record.user, session=record, via_cookie=via_cookie)


def current_principal(request: Request, db: DbSession) -> Principal:
    return _load_session(request, db, stage=sessions.ACTIVE)


def mfa_pending_principal(request: Request, db: DbSession) -> Principal:
    return _load_session(request, db, stage=sessions.MFA_PENDING)


CurrentPrincipal = Annotated[Principal, Depends(current_principal)]


def require(permission: Permission) -> Callable[[Principal], Principal]:
    def dependency(principal: CurrentPrincipal) -> Principal:
        if not principal.can(permission):
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"permission '{permission}' required")
        return principal

    return dependency


def authenticated_agent(request: Request, db: DbSession) -> Agent:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "agent token required")
    token = header[7:].strip()
    agent = db.scalar(select(Agent).where(Agent.token_hash == hash_token(token)))
    if agent is None or agent.status == AgentStatus.REVOKED.value:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid agent token")
    return agent


CurrentAgent = Annotated[Agent, Depends(authenticated_agent)]
