"""
Tests for /api/auth routes and core auth utilities.
All DB interactions use MockSession — no real PostgreSQL required.
"""
import uuid
import pytest
import jwt

from app.core.auth import (
    hash_password, verify_password,
    create_access_token,
)
from app.core.config import settings
from app.models.models import UserRole

from tests.conftest import make_org, make_user, db_result, db_count, TEST_PASSWORD


# ── Pure unit tests (no HTTP) ──────────────────────────────────────

def test_hash_password_is_bcrypt():
    h = hash_password("mysecret")
    assert h.startswith("$2b$")
    assert h != "mysecret"


def test_verify_password_correct():
    h = hash_password("correct")
    assert verify_password("correct", h) is True


def test_verify_password_wrong():
    h = hash_password("correct")
    assert verify_password("wrong", h) is False


def test_access_token_contains_sub_and_type():
    token = create_access_token({"sub": "user-123", "role": "it_admin"})
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    assert payload["sub"] == "user-123"
    assert payload["type"] == "access"


# ── Route: GET /api/auth/login-config ─────────────────────────────

async def test_login_config_no_ldap(auth_client):
    auth_client.mock_session.configure(db_result(None))  # no LDAP org
    resp = await auth_client.get("/api/auth/login-config")
    assert resp.status_code == 200
    assert resp.json() == {"ldap_enabled": False}


# ── Route: POST /api/auth/register ────────────────────────────────

async def test_register_first_user_becomes_admin(auth_client):
    auth_client.mock_session.configure(
        db_count(0),       # 0 total users → first user
        db_result(None),   # no existing user with that email
        db_result(None),   # slug "admin-s-organization" not taken
    )
    payload = {
        "email": "admin@example.com",
        "username": "admin",
        "password": "strongpass1",
        "organization_name": "Acme Corp",
    }
    resp = await auth_client.post("/api/auth/register", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert "access_token" in body
    assert body["user"]["role"] == UserRole.IT_ADMIN
    assert body["user"]["email"] == "admin@example.com"


async def test_register_closed_after_first_user(auth_client):
    auth_client.mock_session.configure(
        db_count(1),       # 1 total user → registration closed (no email lookup)
    )
    payload = {
        "email": "user@example.com",
        "username": "regular",
        "password": "strongpass1",
    }
    resp = await auth_client.post("/api/auth/register", json=payload)
    assert resp.status_code == 403


async def test_register_duplicate_email_returns_400(auth_client):
    existing = make_user(email="taken@example.com")
    auth_client.mock_session.configure(db_count(0), db_result(existing))
    payload = {
        "email": "taken@example.com",
        "username": "someone",
        "password": "strongpass1",
    }
    resp = await auth_client.post("/api/auth/register", json=payload)
    assert resp.status_code == 400
    assert "already registered" in resp.json()["detail"]


async def test_register_short_password_rejected(auth_client):
    resp = await auth_client.post("/api/auth/register", json={
        "email": "x@example.com",
        "username": "x",
        "password": "short",
    })
    assert resp.status_code == 422


# ── Route: POST /api/auth/login ────────────────────────────────────

async def test_login_success(auth_client):
    user = make_user(email="admin@example.com")
    org = make_org(id=user.organization_id)
    auth_client.mock_session.configure(
        db_result(user),
        db_result(org),
    )
    resp = await auth_client.post(
        "/api/auth/login",
        data={"username": "admin@example.com", "password": TEST_PASSWORD},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
    assert body["user"]["email"] == "admin@example.com"


async def test_login_wrong_password_returns_401(auth_client):
    user = make_user(email="admin@example.com")
    org = make_org(id=user.organization_id)
    auth_client.mock_session.configure(
        db_result(user),
        db_result(org),
    )
    resp = await auth_client.post(
        "/api/auth/login",
        data={"username": "admin@example.com", "password": "wrongpassword"},
    )
    assert resp.status_code == 401


async def test_login_inactive_user_returns_403(auth_client):
    user = make_user(email="admin@example.com", is_active=False)
    org = make_org(id=user.organization_id)
    auth_client.mock_session.configure(
        db_result(user),
        db_result(org),
    )
    resp = await auth_client.post(
        "/api/auth/login",
        data={"username": "admin@example.com", "password": TEST_PASSWORD},
    )
    assert resp.status_code == 403


async def test_login_unknown_email_returns_401(auth_client):
    auth_client.mock_session.configure(
        db_result(None),   # user not found
        db_result(None),   # no LDAP org either
    )
    resp = await auth_client.post(
        "/api/auth/login",
        data={"username": "ghost@example.com", "password": "whatever"},
    )
    assert resp.status_code == 401


# ── Route: POST /api/auth/refresh ─────────────────────────────────

async def test_refresh_invalid_token_returns_401(auth_client):
    resp = await auth_client.post("/api/auth/refresh", json={"refresh_token": "not.a.token"})
    assert resp.status_code == 401


async def test_refresh_access_token_rejected(auth_client):
    # Passing an access token where a refresh token is expected should fail.
    user = make_user()
    access_token = create_access_token(
        {"sub": str(user.id), "org": str(user.organization_id), "role": user.role}
    )
    resp = await auth_client.post("/api/auth/refresh", json={"refresh_token": access_token})
    assert resp.status_code == 401


# ── Route: GET /api/auth/me ────────────────────────────────────────

async def test_me_unauthenticated_returns_401(auth_client):
    resp = await auth_client.get("/api/auth/me")
    assert resp.status_code == 401


async def test_me_returns_current_user(auth_client):
    user = make_user()
    auth_client.mock_session.configure(db_result(user))
    token = create_access_token(
        {"sub": str(user.id), "org": str(user.organization_id), "role": user.role}
    )
    resp = await auth_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    assert resp.json()["email"] == user.email


async def test_me_inactive_user_returns_401(auth_client):
    user = make_user(is_active=False)
    auth_client.mock_session.configure(db_result(user))
    token = create_access_token(
        {"sub": str(user.id), "org": str(user.organization_id), "role": user.role}
    )
    resp = await auth_client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 401


async def test_login_locks_account_after_repeated_failures(auth_client):
    user = make_user(email="admin@example.com", failed_login_attempts=4)
    org = make_org(id=user.organization_id)
    auth_client.mock_session.configure(db_result(user), db_result(org))
    resp = await auth_client.post(
        "/api/auth/login",
        data={"username": "admin@example.com", "password": "wrongpassword"},
    )
    assert resp.status_code == 401
    assert user.locked_until is not None
    assert user.failed_login_attempts == 0


async def test_login_rejected_while_locked(auth_client):
    from datetime import datetime, timedelta, timezone
    user = make_user(
        email="admin@example.com",
        locked_until=datetime.now(timezone.utc) + timedelta(minutes=10),
    )
    org = make_org(id=user.organization_id)
    auth_client.mock_session.configure(db_result(user), db_result(org))
    # Even the correct password must be refused while locked
    resp = await auth_client.post(
        "/api/auth/login",
        data={"username": "admin@example.com", "password": TEST_PASSWORD},
    )
    assert resp.status_code == 429
    assert "Retry-After" in resp.headers
