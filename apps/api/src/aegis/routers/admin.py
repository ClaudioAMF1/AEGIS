"""Administration: users, roles and the audit trail."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select

from aegis.models import AuditLog, RoleName, User
from aegis.routers.common import not_found
from aegis.schemas import AuditOut, Page, UserOut
from aegis.security import sessions
from aegis.security.crypto import EMAIL_PATTERN, hash_password, password_problems
from aegis.security.deps import DbSession, Principal, client_ip, require
from aegis.security.rbac import ROLE_DESCRIPTIONS, ROLE_PERMISSIONS, Permission
from aegis.services import audit

router = APIRouter(tags=["admin"])
UserAdmin = Annotated[Principal, Depends(require(Permission.USERS_MANAGE))]
AuditReader = Annotated[Principal, Depends(require(Permission.AUDIT_READ))]
Analyst = Annotated[Principal, Depends(require(Permission.INCIDENTS_WRITE))]


@router.get("/roles")
def roles(_: Analyst) -> list[dict[str, object]]:
    return [
        {
            "name": name,
            "description": ROLE_DESCRIPTIONS[name],
            "permissions": sorted(p.value for p in perms),
        }
        for name, perms in ROLE_PERMISSIONS.items()
    ]


@router.get("/users", response_model=list[UserOut])
def list_users(_: Analyst, db: DbSession) -> list[UserOut]:
    # Analysts need the list to assign incidents; only administrators can modify users.
    return [UserOut.model_validate(u) for u in db.scalars(select(User).order_by(User.email))]


class UserCreate(BaseModel):
    email: Annotated[str, Field(pattern=EMAIL_PATTERN, max_length=320)]
    display_name: Annotated[str, Field(min_length=2, max_length=120)]
    role: RoleName
    password: Annotated[str, Field(max_length=256)]


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: UserCreate, principal: UserAdmin, request: Request, db: DbSession) -> UserOut:
    email = body.email.lower()
    if db.scalar(select(User).where(User.email == email)):
        raise HTTPException(status.HTTP_409_CONFLICT, "e-mail already registered")
    problems = password_problems(body.password, email)
    if problems:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_CONTENT, "password " + "; ".join(problems)
        )
    user = User(
        email=email,
        display_name=body.display_name,
        role=body.role.value,
        password_hash=hash_password(body.password),
    )
    db.add(user)
    db.flush()
    audit.record(
        db,
        action="user.create",
        resource_type="user",
        resource_id=user.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"email": email, "role": body.role},
    )
    db.commit()
    return UserOut.model_validate(user)


class UserPatch(BaseModel):
    role: RoleName | None = None
    is_active: bool | None = None
    display_name: Annotated[str, Field(min_length=2, max_length=120)] | None = None
    revoke_sessions: bool = False


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID, body: UserPatch, principal: UserAdmin, request: Request, db: DbSession
) -> UserOut:
    user = db.get(User, user_id)
    if user is None:
        raise not_found("user")
    if user.id == principal.id and (
        body.role not in (None, RoleName.ADMINISTRATOR) or body.is_active is False
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "administrators cannot demote or deactivate themselves"
        )
    changes: dict[str, object] = {}
    privilege_change = False
    if body.role and body.role.value != user.role:
        changes["role"] = [user.role, body.role.value]
        user.role = body.role.value
        privilege_change = True
    if body.is_active is not None and body.is_active != user.is_active:
        changes["is_active"] = [user.is_active, body.is_active]
        user.is_active = body.is_active
        privilege_change = True
    if body.display_name and body.display_name != user.display_name:
        changes["display_name"] = body.display_name
        user.display_name = body.display_name
    revoked = 0
    if privilege_change or body.revoke_sessions:
        # Privilege changes take effect immediately: existing sessions are invalidated.
        revoked = sessions.revoke_all_for_user(db, user.id)
    audit.record(
        db,
        action="user.update",
        resource_type="user",
        resource_id=user.id,
        actor_id=principal.id,
        actor_email=principal.user.email,
        ip_address=client_ip(request),
        details={"changes": changes, "sessions_revoked": revoked},
    )
    db.commit()
    return UserOut.model_validate(user)


@router.get("/audit", response_model=Page[AuditOut])
def audit_log(
    _: AuditReader,
    db: DbSession,
    action: Annotated[str | None, Query(max_length=64)] = None,
    actor: Annotated[str | None, Query(max_length=320)] = None,
    outcome: Annotated[str | None, Query(max_length=16)] = None,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Page[AuditOut]:
    filters = []
    if action:
        filters.append(AuditLog.action.startswith(action))
    if actor:
        filters.append(AuditLog.actor_email == actor.lower())
    if outcome:
        filters.append(AuditLog.outcome == outcome)
    total = db.scalar(select(func.count()).select_from(AuditLog).where(*filters))
    rows = db.scalars(
        select(AuditLog).where(*filters).order_by(AuditLog.id.desc()).offset(offset).limit(limit)
    ).all()
    return Page(items=[AuditOut.model_validate(r) for r in rows], total=total)
