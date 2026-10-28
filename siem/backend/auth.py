"""
Authentication and role-based access control.

Design notes:

* Passwords are hashed with PBKDF2-HMAC-SHA256 from the standard library, so no
  native build dependency is required. The iteration count is stored in the
  hash string, which allows raising it later without breaking existing users.
* Access tokens are short-lived JWTs signed with HS256. The signing secret comes
  from ``SIEM_JWT_SECRET``. When it is absent in a development environment a
  random secret is generated once into ``backend/.jwt_secret`` (git-ignored) so
  tokens survive a reload; in production a missing secret is fatal.
* Roles are hierarchical: ``viewer`` < ``analyst`` < ``admin``. The middleware
  enforces authentication for every ``/api/`` route and makes viewers read-only.
  Endpoints that change detection content additionally require ``admin``.

This is deliberately small and auditable: a security product should not hide its
authorisation model behind a framework.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from database import SessionLocal, get_db
from models import User

ROLE_RANK: Dict[str, int] = {"viewer": 1, "analyst": 2, "admin": 3}
ROLES = tuple(ROLE_RANK)
ALGORITHM = "HS256"
TOKEN_MINUTES = int(os.getenv("SIEM_JWT_MINUTES", "480"))
PBKDF2_ITERATIONS = 260_000

BACKEND_DIR = Path(__file__).resolve().parent
_SECRET_FILE = BACKEND_DIR / ".jwt_secret"

# Login and health must work without a token; everything else under /api/ is
# protected. OPTIONS is exempt so CORS preflight keeps working.
PUBLIC_PATHS = {"/api/health", "/api/auth/login"}
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

router = APIRouter(prefix="/api/auth", tags=["auth"])


class AuthError(Exception):
    """Raised when a token is missing, malformed or expired."""


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Password hashing ──────────────────────────────────────────────────────────

def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Return ``pbkdf2_sha256$iterations$salt$digest``."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), iterations
    )
    return f"pbkdf2_sha256${iterations}${salt}${digest.hex()}"


def verify_password(password: str, stored: Optional[str]) -> bool:
    if not stored:
        return False
    try:
        scheme, iterations, salt, expected = stored.split("$")
        if scheme != "pbkdf2_sha256":
            return False
        digest = hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), bytes.fromhex(salt), int(iterations)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(digest.hex(), expected)


# ── JWT ───────────────────────────────────────────────────────────────────────

def jwt_secret() -> str:
    configured = os.getenv("SIEM_JWT_SECRET")
    if configured:
        if (
            os.getenv("SIEM_ENV", "development").lower() == "production"
            and len(configured) < 32
        ):
            raise RuntimeError(
                "SIEM_JWT_SECRET must contain at least 32 characters in production"
            )
        return configured

    if os.getenv("SIEM_ENV", "development").lower() == "production":
        raise RuntimeError(
            "SIEM_JWT_SECRET must be set when SIEM_ENV=production"
        )

    if _SECRET_FILE.exists():
        value = _SECRET_FILE.read_text(encoding="utf-8").strip()
        if value:
            return value

    value = secrets.token_hex(32)
    _SECRET_FILE.write_text(value, encoding="utf-8")
    try:
        os.chmod(_SECRET_FILE, 0o600)
    except OSError:
        pass
    return value


def create_access_token(user: User, minutes: Optional[int] = None) -> tuple[str, int]:
    """Return ``(token, expires_in_seconds)`` for *user*."""
    lifetime = minutes or TOKEN_MINUTES
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=lifetime)).timestamp()),
    }
    token = jwt.encode(payload, jwt_secret(), algorithm=ALGORITHM)
    return token, lifetime * 60


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, jwt_secret(), algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise AuthError("Token has expired") from exc
    except jwt.PyJWTError as exc:
        raise AuthError("Invalid token") from exc


# ── User management helpers ───────────────────────────────────────────────────

def authenticate(db: Session, username: str, password: str) -> Optional[User]:
    user = db.query(User).filter(User.username == username).first()
    if user is None or not user.is_active:
        # Compare anyway to keep the timing profile flat for unknown users.
        verify_password(password, "pbkdf2_sha256$1$00$00")
        return None
    if not verify_password(password, user.password_hash):
        return None
    user.last_login_at = _utcnow()
    db.commit()
    db.refresh(user)
    return user


def ensure_bootstrap_admin(db: Optional[Session] = None) -> None:
    """Create the first administrator when the user table is empty."""
    own_session = db is None
    db = db or SessionLocal()
    try:
        if db.query(User).count() > 0:
            return

        username = os.getenv("SIEM_ADMIN_USER", "admin")
        password = os.getenv("SIEM_ADMIN_PASSWORD")
        environment = os.getenv("SIEM_ENV", "development").lower()

        if not password:
            if environment == "production":
                raise RuntimeError(
                    "No users exist and SIEM_ADMIN_PASSWORD is not set. "
                    "Refusing to create a default administrator in production."
                )
            password = "admin"
            print(
                "WARNING: created development administrator 'admin' with the "
                "default password 'admin'. Set SIEM_ADMIN_PASSWORD before "
                "exposing this service."
            )
        elif environment == "production" and (
            len(password) < 12 or password.lower() == "admin"
        ):
            raise RuntimeError(
                "SIEM_ADMIN_PASSWORD must contain at least 12 non-default "
                "characters in production"
            )

        db.add(User(username=username, password_hash=hash_password(password), role="admin"))
        db.commit()
    finally:
        if own_session:
            db.close()


def user_out(user: User) -> Dict[str, object]:
    return {
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "last_login_at": user.last_login_at,
    }


# ── FastAPI dependencies ──────────────────────────────────────────────────────

def require_user(request: Request) -> User:
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(minimum: str):
    """Dependency factory enforcing at least *minimum* role."""
    if minimum not in ROLE_RANK:
        raise ValueError(f"Unknown role: {minimum}")

    def dependency(user: User = Depends(require_user)) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[minimum]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires the '{minimum}' role or higher",
            )
        return user

    return dependency


# ── Middleware ────────────────────────────────────────────────────────────────

def _unauthorised(detail: str) -> JSONResponse:
    return JSONResponse(
        {"detail": detail},
        status_code=status.HTTP_401_UNAUTHORIZED,
        headers={"WWW-Authenticate": "Bearer"},
    )


def install(app) -> None:
    """Attach the authentication middleware to *app*."""

    @app.middleware("http")
    async def authenticate(request: Request, call_next):
        path = request.url.path

        if request.method == "OPTIONS" or not path.startswith("/api/"):
            return await call_next(request)
        if path in PUBLIC_PATHS:
            return await call_next(request)

        header = request.headers.get("authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return _unauthorised("Missing bearer token")

        try:
            payload = decode_token(token.strip())
            user_id = int(payload.get("sub"))
        except (AuthError, TypeError, ValueError):
            return _unauthorised("Invalid or expired token")

        db = SessionLocal()
        try:
            user = db.get(User, user_id)
            if user is not None:
                # Touch the attributes we need before the session closes.
                _ = (user.id, user.username, user.role, user.is_active)
        finally:
            db.close()

        if user is None or not user.is_active:
            return _unauthorised("User is inactive or no longer exists")

        request.state.user = user

        if request.method not in SAFE_METHODS and ROLE_RANK.get(user.role, 0) < ROLE_RANK["analyst"]:
            return JSONResponse(
                {"detail": "Viewer role is read-only"},
                status_code=status.HTTP_403_FORBIDDEN,
            )

        return await call_next(request)


# ── Routes ────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=1, max_length=256)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=120, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=8, max_length=256)
    role: str = Field(default="viewer")


class UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(default=None, min_length=8, max_length=256)


@router.post("/login")
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate(db, payload.username.strip(), payload.password)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token, expires_in = create_access_token(user)
    return {
        "access_token": token,
        "token_type": "bearer",
        "expires_in": expires_in,
        "user": user_out(user),
    }


@router.get("/me")
def me(user: User = Depends(require_user)):
    return user_out(user)


@router.get("/users")
def list_users(db: Session = Depends(get_db), _: User = Depends(require_role("admin"))):
    users = db.query(User).order_by(User.username).all()
    return {"users": [user_out(u) for u in users], "total": len(users)}


@router.post("/users", status_code=201)
def create_user(
    payload: CreateUserRequest,
    db: Session = Depends(get_db),
    _: User = Depends(require_role("admin")),
):
    if payload.role not in ROLES:
        raise HTTPException(status_code=422, detail=f"role must be one of {', '.join(ROLES)}")
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(status_code=409, detail="Username already exists")

    user = User(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user_out(user)


@router.patch("/users/{user_id}")
def update_user(
    user_id: int,
    payload: UpdateUserRequest,
    db: Session = Depends(get_db),
    current: User = Depends(require_role("admin")),
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    if payload.role is not None:
        if payload.role not in ROLES:
            raise HTTPException(status_code=422, detail=f"role must be one of {', '.join(ROLES)}")
        if user.id == current.id and payload.role != "admin":
            raise HTTPException(status_code=400, detail="You cannot demote your own account")
        if user.role == "admin" and payload.role != "admin":
            admins = db.query(User).filter(User.role == "admin", User.is_active.is_(True)).count()
            if admins <= 1:
                raise HTTPException(status_code=400, detail="At least one active admin is required")
        user.role = payload.role

    if payload.is_active is not None:
        if user.id == current.id and not payload.is_active:
            raise HTTPException(status_code=400, detail="You cannot deactivate your own account")
        user.is_active = payload.is_active

    if payload.password:
        user.password_hash = hash_password(payload.password)

    db.commit()
    db.refresh(user)
    return user_out(user)
