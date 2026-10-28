"""
Database configuration and session management for the ARGUS backend.

Defaults to SQLite for zero-dependency local operation. Set
``ARGUS_DATABASE_URL`` (for example
``postgresql+psycopg://argus:argus@localhost:5432/argus``) to point the API at
PostgreSQL instead. Schema changes are applied with Alembic.
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

_DB_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_URL = f"sqlite:///{os.path.join(_DB_DIR, 'argus.db')}"

SQLALCHEMY_DATABASE_URL = os.getenv("ARGUS_DATABASE_URL", _DEFAULT_URL)

_engine_kwargs = {"pool_pre_ping": True}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(SQLALCHEMY_DATABASE_URL, **_engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Apply database migrations up to the latest revision."""
    from migrations import upgrade_database

    upgrade_database()
