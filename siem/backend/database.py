"""
Database configuration and session management for the SIEM backend.

Uses SQLAlchemy with SQLite for zero-dependency local operation.
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# SQLite database file in the backend directory
_DB_DIR = os.path.dirname(os.path.abspath(__file__))
SQLALCHEMY_DATABASE_URL = f"sqlite:///{os.path.join(_DB_DIR, 'siem.db')}"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},  # Required for SQLite
)

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
    """Create all database tables. Safe to call multiple times."""
    from models import (  # noqa: F401 — import so Base.metadata knows about them
        SecurityEvent,
        Alert,
        Incident,
        DetectionRule,
    )
    Base.metadata.create_all(bind=engine)
