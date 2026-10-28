"""Shared pytest fixtures for the ARGUS backend.

The database URL is set before ``database`` is imported. Every test gets clean
assets, findings and scans while the user table (and its bootstrap admin) is
kept across the session.
"""

from __future__ import annotations

import os
import sys
import tempfile

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

_TMP_DIR = tempfile.mkdtemp(prefix="argus-tests-")
os.environ.setdefault("ARGUS_DATABASE_URL", f"sqlite:///{os.path.join(_TMP_DIR, 'test.db')}")
os.environ.setdefault("ARGUS_JWT_SECRET", "test-secret-not-for-production")
os.environ.setdefault("ARGUS_ADMIN_USER", "admin")
os.environ.setdefault("ARGUS_ADMIN_PASSWORD", "test-admin-password")
os.environ.setdefault("ARGUS_ENV", "test")

import pytest  # noqa: E402

ADMIN_PASSWORD = "test-admin-password"
LAB = "acme-lab.local"


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


@pytest.fixture(scope="session")
def admin_token():
    from fastapi.testclient import TestClient

    import main
    from database import init_db

    init_db()
    with TestClient(main.app) as test_client:
        _ensure_admin()
        response = test_client.post(
            "/api/auth/login", json={"username": "admin", "password": ADMIN_PASSWORD}
        )
        assert response.status_code == 200, response.text
        return response.json()["access_token"]


@pytest.fixture()
def client(admin_token):
    from fastapi.testclient import TestClient

    import main
    from database import SessionLocal, init_db
    from models import Asset, Finding, Scan

    init_db()
    db = SessionLocal()
    try:
        db.query(Finding).delete()
        db.query(Scan).delete()
        db.query(Asset).delete()
        db.commit()
    finally:
        db.close()

    with TestClient(main.app) as test_client:
        test_client.headers.update({"Authorization": f"Bearer {admin_token}"})
        yield test_client


@pytest.fixture()
def anon_client():
    from fastapi.testclient import TestClient

    import main
    from database import init_db

    init_db()
    with TestClient(main.app) as test_client:
        yield test_client


def _role_token(role: str, username: str) -> str:
    from fastapi.testclient import TestClient

    import main
    from auth import hash_password
    from database import SessionLocal, init_db
    from models import User

    init_db()
    db = SessionLocal()
    try:
        if db.query(User).filter(User.username == username).first() is None:
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
def db_session():
    from database import SessionLocal, init_db
    from models import Asset, Finding, Scan

    init_db()
    db = SessionLocal()
    try:
        db.query(Finding).delete()
        db.query(Scan).delete()
        db.query(Asset).delete()
        db.commit()
        yield db
    finally:
        db.close()


def run_scans(client, count: int = 1):
    """Run *count* lab scans and return the decoded responses."""
    results = []
    for _ in range(count):
        response = client.post("/api/scan", json={"domain": LAB})
        assert response.status_code == 200, response.text
        results.append(response.json())
    return results
