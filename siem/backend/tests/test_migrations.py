"""Alembic revision state and schema/model consistency."""

from __future__ import annotations

from sqlalchemy import inspect
from alembic.script import ScriptDirectory

from database import Base, engine
import migrations


def _head() -> str:
    return ScriptDirectory.from_config(migrations.alembic_config()).get_current_head()


def test_database_is_at_head():
    migrations.upgrade_database()
    assert migrations.current_revision() == _head()


def test_upgrade_is_idempotent():
    migrations.upgrade_database()
    migrations.upgrade_database()
    assert migrations.current_revision() == _head()


def test_every_model_table_exists():
    migrations.upgrade_database()
    tables = set(inspect(engine).get_table_names())
    assert set(Base.metadata.tables) <= tables


def test_users_table_has_unique_username():
    migrations.upgrade_database()
    inspector = inspect(engine)
    unique_indexes = [
        index
        for index in inspector.get_indexes("users")
        if index.get("unique")
    ]
    assert any(index["column_names"] == ["username"] for index in unique_indexes)
