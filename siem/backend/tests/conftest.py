"""Shared pytest fixtures.

The database URL must be set *before* ``database`` is imported, so it happens at
module import time here. Each test gets a clean alerts/incidents/events slate
while the seeded rule catalogue is rebuilt by the app's startup hook.
"""

from __future__ import annotations

import os
import sys
import tempfile

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

_TMP_DIR = tempfile.mkdtemp(prefix="siem-tests-")
os.environ.setdefault("SIEM_DATABASE_URL", f"sqlite:///{os.path.join(_TMP_DIR, 'test.db')}")
os.environ.setdefault("SIEM_SIGMA_RULES_DIR", os.path.join(BACKEND_DIR, "rules"))
os.environ.setdefault("SIEM_JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("SIEM_ADMIN_USER", "admin")
os.environ.setdefault("SIEM_ADMIN_PASSWORD", "test-admin-password")
os.environ.setdefault("SIEM_ENV", "test")

import pytest  # noqa: E402

ADMIN_PASSWORD = "test-admin-password"


def _ensure_admin() -> None:
    """Make the test admin deterministic even if the environment sets another password."""
    from auth import hash_password
    from database import SessionLocal
    from models import User

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "admin").first()
        if user is None:
            db.add(
                User(
                    username="admin",
                    password_hash=hash_password(ADMIN_PASSWORD),
                    role="admin",
                )
            )
        else:
            user.password_hash = hash_password(ADMIN_PASSWORD)
            user.role = "admin"
            user.is_active = True
        db.commit()
    finally:
        db.close()


def make_event(
    event_id: int,
    account: str = "user1",
    timestamp: str = "2026-10-24T10:00:00+00:00",
    source_ip: str | None = None,
    computer: str = "WS-001",
    event_type: str = "Authentication",
    severity: str = "Low",
    raw: dict | None = None,
) -> dict:
    """Build an ingest payload in the platform's canonical shape."""
    return {
        "timestamp": timestamp,
        "event_id": event_id,
        "source": "Windows Security",
        "account": account,
        "source_ip": source_ip,
        "computer_name": computer,
        "event_type": event_type,
        "severity": severity,
        "raw_data": raw or {},
    }


@pytest.fixture(scope="session")
def admin_token():
    """Log in once per test session; PBKDF2 is intentionally expensive."""
    from fastapi.testclient import TestClient

    import main
    from database import init_db

    init_db()
    with TestClient(main.app) as test_client:
        _ensure_admin()
        response = test_client.post(
            "/api/auth/login",
            json={"username": "admin", "password": ADMIN_PASSWORD},
        )
        assert response.status_code == 200, response.text
        return response.json()["access_token"]


@pytest.fixture()
def client(admin_token):
    from fastapi.testclient import TestClient

    import main
    from database import SessionLocal, init_db
    from models import Alert, Incident, SecurityEvent

    init_db()
    db = SessionLocal()
    try:
        db.query(Alert).delete()
        db.query(Incident).delete()
        db.query(SecurityEvent).delete()
        db.commit()
    finally:
        db.close()

    with TestClient(main.app) as test_client:
        test_client.headers.update({"Authorization": f"Bearer {admin_token}"})
        yield test_client


@pytest.fixture()
def anon_client():
    """Unauthenticated client, for authorisation tests."""
    from fastapi.testclient import TestClient

    import main
    from database import init_db

    init_db()
    with TestClient(main.app) as test_client:
        yield test_client


def _role_token(role: str, username: str) -> str:
    from fastapi.testclient import TestClient

    import main
    from database import SessionLocal, init_db
    from models import User

    init_db()
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first() is None:
            from auth import hash_password

            db.add(User(username=username, password_hash=hash_password("role-password-1"), role=role))
            db.commit()
    finally:
        db.close()

    with TestClient(main.app) as test_client:
        response = test_client.post(
            "/api/auth/login", json={"username": username, "password": "role-password-1"}
        )
        assert response.status_code == 200, response.text
        return response.json()["access_token"]


@pytest.fixture()
def viewer_client():
    from fastapi.testclient import TestClient

    import main

    token = _role_token("viewer", "test-viewer")
    with TestClient(main.app) as test_client:
        test_client.headers.update({"Authorization": f"Bearer {token}"})
        yield test_client


@pytest.fixture()
def analyst_client():
    from fastapi.testclient import TestClient

    import main

    token = _role_token("analyst", "test-analyst")
    with TestClient(main.app) as test_client:
        test_client.headers.update({"Authorization": f"Bearer {token}"})
        yield test_client


@pytest.fixture()
def seeded_client(client):
    """Client with a small, deliberate attack scenario ingested."""

    def _seed(events: list[dict]):
        response = client.post("/api/events/ingest", json=events)
        assert response.status_code == 200, response.text
        return response.json()

    return client, _seed
