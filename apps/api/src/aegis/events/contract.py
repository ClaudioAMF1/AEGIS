"""AEGIS Common Event (ACE) contract, version 1.0.

This module is the single source of truth for the telemetry wire format. The JSON Schema in
``packages/event-schemas`` is generated from it (``aegis export-schemas``) and the contract
tests guarantee that the committed schema, the Rust agent and the API agree.

Design notes
* ``event_id`` is produced by the sender (UUID, v7 recommended) and is the idempotency key.
* ``occurred_at`` must carry a timezone. ``ingested_at`` is assigned by the server.
* Only the minimum fields needed for detection are collected. Command lines are the most
  sensitive field and are truncated to 4 KiB; file *contents* and network payloads are never
  part of the contract.
"""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator

SCHEMA_VERSION = "1.0"

ShortStr = Annotated[str, Field(max_length=255)]
Scalar = str | int | float | bool | None


class Category(StrEnum):
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    AUTHENTICATION = "authentication"
    SYSTEM = "system"


ACTIONS: dict[Category, set[str]] = {
    Category.PROCESS: {"start", "exit"},
    Category.NETWORK: {"connect", "listen", "accept"},
    Category.FILE: {"create", "modify", "delete", "rename", "chmod"},
    Category.AUTHENTICATION: {"login_success", "login_failure", "logout", "privilege_escalation"},
    Category.SYSTEM: {"agent_start", "agent_stop", "service_start", "service_stop", "module_load"},
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class HostInfo(_Strict):
    hostname: Annotated[str, Field(min_length=1, max_length=255, pattern=r"^[A-Za-z0-9._-]+$")]
    os: ShortStr | None = None
    ip: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("ip")
    @classmethod
    def _valid_ips(cls, values: list[str]) -> list[str]:
        for value in values:
            ipaddress.ip_address(value)
        return values


class UserInfo(_Strict):
    name: Annotated[str, Field(min_length=1, max_length=128)]
    uid: int | None = Field(default=None, ge=0)


class ProcessInfo(_Strict):
    pid: int = Field(ge=0)
    ppid: int | None = Field(default=None, ge=0)
    name: Annotated[str, Field(min_length=1, max_length=255)]
    executable: Annotated[str, Field(max_length=1024)] | None = None
    command_line: Annotated[str, Field(max_length=4096)] | None = None
    parent_name: ShortStr | None = None
    parent_executable: Annotated[str, Field(max_length=1024)] | None = None
    working_directory: Annotated[str, Field(max_length=1024)] | None = None
    hash_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")] | None = None
    exit_code: int | None = None


class NetworkInfo(_Strict):
    direction: Literal["outbound", "inbound", "local"]
    protocol: Literal["tcp", "udp", "tcp6", "udp6"]
    src_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_ip: str
    dst_port: int = Field(ge=0, le=65535)
    state: Annotated[str, Field(max_length=32)] | None = None

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _valid_ip(cls, value: str) -> str:
        return str(ipaddress.ip_address(value))


class FileInfo(_Strict):
    path: Annotated[str, Field(min_length=1, max_length=1024)]
    target_path: Annotated[str, Field(max_length=1024)] | None = None
    hash_sha256: Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")] | None = None
    mode: Annotated[str, Field(pattern=r"^[0-7]{3,4}$")] | None = None
    size: int | None = Field(default=None, ge=0)


class AuthInfo(_Strict):
    method: Annotated[str, Field(max_length=32)]
    outcome: Literal["success", "failure"]
    source_ip: str | None = None
    target_user: Annotated[str, Field(max_length=128)] | None = None
    service: Annotated[str, Field(max_length=64)] | None = None

    @field_validator("source_ip")
    @classmethod
    def _valid_ip(cls, value: str | None) -> str | None:
        return None if value is None else str(ipaddress.ip_address(value))


class EventIn(_Strict):
    """One telemetry event as sent by an agent or simulator."""

    schema_version: Literal["1.0"] = "1.0"
    event_id: UUID
    occurred_at: AwareDatetime
    seq: int | None = Field(default=None, ge=0, description="Per-agent monotonic counter")
    category: Category
    action: Annotated[str, Field(min_length=1, max_length=32)]
    host: HostInfo
    user: UserInfo | None = None
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None
    file: FileInfo | None = None
    auth: AuthInfo | None = None
    attributes: dict[Annotated[str, Field(max_length=64)], Scalar] = Field(
        default_factory=dict, max_length=32
    )

    @model_validator(mode="after")
    def _consistent(self) -> EventIn:
        allowed = ACTIONS[self.category]
        if self.action not in allowed:
            raise ValueError(f"action '{self.action}' not valid for category '{self.category}'")
        required = {
            Category.PROCESS: self.process,
            Category.NETWORK: self.network,
            Category.FILE: self.file,
            Category.AUTHENTICATION: self.auth,
        }.get(self.category, True)
        if required is None:
            raise ValueError(f"category '{self.category}' requires the '{self.category}' object")
        for key, value in self.attributes.items():
            if isinstance(value, str) and len(value) > 512:
                raise ValueError(f"attribute '{key}' exceeds 512 characters")
        return self


class EventBatch(_Strict):
    events: list[EventIn] = Field(min_length=1, max_length=500)
    agent_version: Annotated[str, Field(max_length=32)] | None = None
    buffer_depth: int | None = Field(default=None, ge=0)


class RejectedEvent(BaseModel):
    index: int
    event_id: str | None
    reason: str


class IngestResult(BaseModel):
    accepted: int
    duplicates: int
    rejected: list[RejectedEvent]
    ingested_at: datetime
    pipeline: str


class HeartbeatIn(_Strict):
    agent_version: Annotated[str, Field(max_length=32)]
    host: HostInfo
    buffer_depth: int = Field(ge=0)
    dropped_events: int = Field(default=0, ge=0)
    uptime_seconds: int = Field(ge=0)


class PendingAction(BaseModel):
    id: str
    action_type: str
    parameters: dict[str, Scalar]


class HeartbeatOut(BaseModel):
    server_time: datetime
    config: dict[str, object]
    pending_actions: list[PendingAction]
