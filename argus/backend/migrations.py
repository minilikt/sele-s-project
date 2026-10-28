"""
Programmatic Alembic entry point for ARGUS.

Existing pre-Alembic databases are stamped with the baseline revision and then
upgraded, so the demo database is not discarded.
"""

from __future__ import annotations

import threading
from pathlib import Path
from typing import Optional

from alembic import command
from alembic.config import Config
from sqlalchemy import inspect

from database import SQLALCHEMY_DATABASE_URL, engine

BACKEND_DIR = Path(__file__).resolve().parent
ALEMBIC_INI = BACKEND_DIR / "alembic.ini"
BASELINE_REVISION = "0001_initial"

_lock = threading.Lock()
_upgraded: set[str] = set()


def alembic_config() -> Config:
    config = Config(str(ALEMBIC_INI))
    config.set_main_option("script_location", str(BACKEND_DIR / "alembic"))
    return config


def current_revision() -> Optional[str]:
    inspector = inspect(engine)
    if "alembic_version" not in inspector.get_table_names():
        return None
    with engine.connect() as connection:
        row = connection.exec_driver_sql("SELECT version_num FROM alembic_version").fetchone()
    return row[0] if row else None


def upgrade_database(force: bool = False) -> None:
    key = SQLALCHEMY_DATABASE_URL
    with _lock:
        if key in _upgraded and not force:
            return

        tables = set(inspect(engine).get_table_names())
        is_legacy = (
            "alembic_version" not in tables
            and {"assets", "findings", "scans"} <= tables
        )
        if is_legacy:
            command.stamp(alembic_config(), BASELINE_REVISION)

        command.upgrade(alembic_config(), "head")
        _upgraded.add(key)
