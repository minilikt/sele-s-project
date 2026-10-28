"""
Database configuration and session management for the SIEM backend.

Defaults to SQLite for zero-dependency local operation. Set
``SIEM_DATABASE_URL`` (for example
``postgresql+psycopg://siem:siem@localhost:5432/siem``) to point the API at
PostgreSQL instead.
"""

import os

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

_DB_DIR = os.path.dirname(os.path.abspath(__file__))
_DEFAULT_URL = f"sqlite:///{os.path.join(_DB_DIR, 'siem.db')}"

SQLALCHEMY_DATABASE_URL = os.getenv("SIEM_DATABASE_URL", _DEFAULT_URL)

_engine_kwargs = {"pool_pre_ping": True}
if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    # SQLite needs this for FastAPI's threadpool; other backends must not get it.
    _engine_kwargs["connect_args"] = {"check_same_thread": False}

engine = create_engine(SQLALCHEMY_DATABASE_URL, **_engine_kwargs)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Apply database migrations up to the latest revision."""
    from migrations import upgrade_database

    upgrade_database()
