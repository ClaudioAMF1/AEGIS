"""Runtime configuration.

Every value comes from environment variables (prefix ``AEGIS_``) or an ``.env`` file.
There are no default secrets: ``AEGIS_SECRET_KEY`` must be provided outside of tests.
"""

from __future__ import annotations

from enum import StrEnum
from functools import lru_cache

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class PipelineMode(StrEnum):
    INLINE = "inline"  # detection runs in the API process right after persistence
    BROKER = "broker"  # events are published to Redis Streams and consumed by the worker


class Environment(StrEnum):
    DEVELOPMENT = "development"
    TEST = "test"
    PRODUCTION = "production"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    environment: Environment = Environment.DEVELOPMENT
    database_url: str = "sqlite:///./aegis-dev.db"
    redis_url: str | None = None
    secret_key: SecretStr = Field(min_length=32)

    pipeline_mode: PipelineMode = PipelineMode.INLINE
    stream_name: str = "aegis.events"
    stream_max_pending: int = 50_000  # backpressure threshold for the broker

    # Sessions
    session_cookie_name: str = "aegis_session"
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12
    cookie_secure: bool = True

    # Abuse protection
    login_max_attempts: int = 5
    login_window_seconds: int = 300
    lockout_minutes: int = 15

    # Ingestion limits
    ingest_max_batch: int = 500
    ingest_max_body_bytes: int = 2_000_000
    ingest_max_clock_skew_minutes: int = 10
    ingest_max_event_age_days: int = 7

    # Retention
    event_retention_days: int = 30

    # Detection
    rules_dir: str = "../../rules"
    scenarios_dir: str = "../../simulations/scenarios"
    alert_suppression_minutes: int = 15
    incident_grouping_minutes: int = 30

    # AI assistant (optional)
    anthropic_api_key: SecretStr | None = None
    assistant_model: str = "claude-sonnet-5-5"

    # Threat intelligence (optional external enrichment)
    intel_external_enabled: bool = False
    abuseipdb_api_key: SecretStr | None = None

    cors_origins: list[str] = Field(default_factory=list)

    @field_validator("database_url")
    @classmethod
    def _normalize_pg(cls, value: str) -> str:
        # Allow plain postgres:// URLs; we always use the psycopg 3 driver.
        if value.startswith("postgres://"):
            value = "postgresql://" + value.removeprefix("postgres://")
        if value.startswith("postgresql://"):
            value = "postgresql+psycopg://" + value.removeprefix("postgresql://")
        return value

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


@lru_cache
def get_settings() -> Settings:
    return Settings()
