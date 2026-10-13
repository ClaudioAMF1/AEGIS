"""Alembic migrations bundled with the package (no alembic.ini required)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from aegis.config import get_settings

_HERE = Path(__file__).parent


def alembic_config(url: str | None = None) -> Config:
    config = Config()
    config.set_main_option("script_location", str(_HERE))
    config.set_main_option(
        "sqlalchemy.url", (url or get_settings().database_url).replace("%", "%%")
    )
    return config


def upgrade_head(url: str | None = None) -> None:
    command.upgrade(alembic_config(url), "head")
