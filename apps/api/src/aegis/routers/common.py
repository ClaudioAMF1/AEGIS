"""Shared query helpers for routers."""

from __future__ import annotations

import base64
import uuid
from datetime import datetime
from typing import Any

from fastapi import HTTPException, status
from sqlalchemy import ColumnElement, true

from aegis.schemas import Scope


def scope_clause(column: Any, scope: Scope) -> ColumnElement[bool]:
    if scope == Scope.LIVE:
        return column.is_(False)  # type: ignore[no-any-return]
    if scope == Scope.DEMO:
        return column.is_(True)  # type: ignore[no-any-return]
    return true()


def encode_cursor(ts: datetime, ident: uuid.UUID) -> str:
    return base64.urlsafe_b64encode(f"{ts.isoformat()}|{ident}".encode()).decode()


def decode_cursor(cursor: str) -> tuple[datetime, uuid.UUID]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts, ident = raw.split("|", 1)
        return datetime.fromisoformat(ts), uuid.UUID(ident)
    except (ValueError, UnicodeDecodeError) as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid cursor") from exc


def not_found(what: str) -> HTTPException:
    return HTTPException(status.HTTP_404_NOT_FOUND, f"{what} not found")
