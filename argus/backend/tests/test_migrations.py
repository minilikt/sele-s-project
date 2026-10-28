"""Alembic revision state and schema/model consistency."""

from __future__ import annotations

from alembic.script import ScriptDirectory
from sqlalchemy import inspect

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
    assert set(Base.metadata.tables) <= set(inspect(engine).get_table_names())


def test_username_is_unique():
    migrations.upgrade_database()
    indexes = [i for i in inspect(engine).get_indexes("users") if i.get("unique")]
    assert any(i["column_names"] == ["username"] for i in indexes)
