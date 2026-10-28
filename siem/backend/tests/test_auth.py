"""Authentication, JWT handling and role-based access control."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest

import auth


class TestPasswordHashing:
    def test_round_trip(self):
        stored = auth.hash_password("correct horse battery staple")
        assert auth.verify_password("correct horse battery staple", stored)

    def test_wrong_password_rejected(self):
        stored = auth.hash_password("secret-password")
        assert not auth.verify_password("secret-password2", stored)

    def test_hash_is_salted(self):
        assert auth.hash_password("same") != auth.hash_password("same")

    def test_malformed_hash_is_rejected(self):
        assert not auth.verify_password("x", "not-a-hash")
        assert not auth.verify_password("x", None)
        assert not auth.verify_password("x", "md5$1$aa$bb")


class TestLogin:
    def test_successful_login(self, anon_client):
        response = anon_client.post(
            "/api/auth/login", json={"username": "admin", "password": "test-admin-password"}
        )
        assert response.status_code == 200, response.text
        body = response.json()
        assert body["token_type"] == "bearer"
        assert body["access_token"]
        assert body["user"]["role"] == "admin"
        assert "password_hash" not in body["user"]

    def test_wrong_password(self, anon_client):
        response = anon_client.post(
            "/api/auth/login", json={"username": "admin", "password": "wrong"}
        )
        assert response.status_code == 401

    def test_unknown_user(self, anon_client):
        response = anon_client.post(
            "/api/auth/login", json={"username": "nobody", "password": "whatever"}
        )
        assert response.status_code == 401

    def test_missing_fields_are_validated(self, anon_client):
        assert anon_client.post("/api/auth/login", json={}).status_code == 422


class TestTokenEnforcement:
    def test_health_is_public(self, anon_client):
        assert anon_client.get("/api/health").status_code == 200

    def test_api_requires_a_token(self, anon_client):
        response = anon_client.get("/api/alerts")
        assert response.status_code == 401
        assert response.headers["www-authenticate"] == "Bearer"

    def test_malformed_token_rejected(self, anon_client):
        response = anon_client.get("/api/alerts", headers={"Authorization": "Bearer nonsense"})
        assert response.status_code == 401

    def test_expired_token_rejected(self, anon_client):
        expired = jwt.encode(
            {
                "sub": "1",
                "exp": datetime.now(timezone.utc) - timedelta(minutes=1),
            },
            auth.jwt_secret(),
            algorithm="HS256",
        )
        response = anon_client.get("/api/alerts", headers={"Authorization": f"Bearer {expired}"})
        assert response.status_code == 401

    def test_token_signed_with_wrong_secret_rejected(self, anon_client):
        forged = jwt.encode(
            {"sub": "1", "exp": datetime.now(timezone.utc) + timedelta(minutes=5)},
            "not-the-real-secret",
            algorithm="HS256",
        )
        response = anon_client.get("/api/alerts", headers={"Authorization": f"Bearer {forged}"})
        assert response.status_code == 401

    def test_me_returns_current_user(self, client):
        body = client.get("/api/auth/me").json()
        assert body["username"] == "admin"
        assert body["role"] == "admin"


class TestRoleEnforcement:
    def test_viewer_can_read(self, viewer_client):
        assert viewer_client.get("/api/alerts").status_code == 200
        assert viewer_client.get("/api/incidents").status_code == 200

    def test_viewer_cannot_write(self, viewer_client):
        response = viewer_client.post("/api/detection/run")
        assert response.status_code == 403
        assert "read-only" in response.json()["detail"]

    def test_viewer_cannot_ingest(self, viewer_client):
        response = viewer_client.post("/api/events/ingest", json=[])
        assert response.status_code == 403

    def test_analyst_can_run_detection(self, analyst_client):
        assert analyst_client.post("/api/detection/run").status_code == 200

    def test_analyst_cannot_change_rules(self, analyst_client):
        rule = analyst_client.get("/api/detection/rules").json()["rules"][0]
        response = analyst_client.patch(
            f"/api/detection/rules/{rule['id']}", json={"enabled": False}
        )
        assert response.status_code == 403

    def test_analyst_cannot_reload_sigma_rules(self, analyst_client):
        assert analyst_client.post("/api/detection/reload").status_code == 403

    def test_analyst_cannot_manage_users(self, analyst_client):
        assert analyst_client.get("/api/auth/users").status_code == 403
        assert analyst_client.post(
            "/api/auth/users",
            json={"username": "sneaky", "password": "password-123", "role": "admin"},
        ).status_code == 403

    def test_analyst_cannot_rebuild_incidents(self, analyst_client):
        response = analyst_client.post("/api/incidents/correlate?rebuild=true")
        assert response.status_code == 403

    def test_analyst_can_correlate_without_rebuild(self, analyst_client):
        assert analyst_client.post("/api/incidents/correlate").status_code == 200

    def test_admin_can_change_rules(self, client):
        rule = client.get("/api/detection/rules").json()["rules"][0]
        response = client.patch(
            f"/api/detection/rules/{rule['id']}", json={"enabled": rule["enabled"]}
        )
        assert response.status_code == 200


class TestUserManagement:
    def test_admin_can_create_and_list_users(self, client):
        created = client.post(
            "/api/auth/users",
            json={"username": "new.analyst", "password": "analyst-pass-1", "role": "analyst"},
        )
        assert created.status_code == 201, created.text
        assert created.json()["role"] == "analyst"

        users = client.get("/api/auth/users").json()
        assert any(u["username"] == "new.analyst" for u in users["users"])

    def test_duplicate_username_rejected(self, client):
        response = client.post(
            "/api/auth/users",
            json={"username": "admin", "password": "another-pass-1", "role": "viewer"},
        )
        assert response.status_code == 409

    def test_invalid_role_rejected(self, client):
        response = client.post(
            "/api/auth/users",
            json={"username": "weird", "password": "another-pass-1", "role": "superuser"},
        )
        assert response.status_code == 422

    def test_admin_cannot_demote_self(self, client):
        me = client.get("/api/auth/me").json()
        response = client.patch(f"/api/auth/users/{me['id']}", json={"role": "viewer"})
        assert response.status_code == 400

    def test_admin_cannot_deactivate_self(self, client):
        me = client.get("/api/auth/me").json()
        response = client.patch(f"/api/auth/users/{me['id']}", json={"is_active": False})
        assert response.status_code == 400

    def test_deactivated_user_loses_access(self, client):
        client.post(
            "/api/auth/users",
            json={"username": "temporary", "password": "temporary-pass-1", "role": "viewer"},
        )
        from fastapi.testclient import TestClient

        import main

        with TestClient(main.app) as other:
            token = other.post(
                "/api/auth/login",
                json={"username": "temporary", "password": "temporary-pass-1"},
            ).json()["access_token"]

        users = client.get("/api/auth/users").json()["users"]
        target = next(u for u in users if u["username"] == "temporary")
        client.patch(f"/api/auth/users/{target['id']}", json={"is_active": False})

        from fastapi.testclient import TestClient

        import main

        with TestClient(main.app) as other:
            response = other.get(
                "/api/alerts", headers={"Authorization": f"Bearer {token}"}
            )
            assert response.status_code == 401
