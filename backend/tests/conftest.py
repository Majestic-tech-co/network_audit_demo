"""
Shared fixtures for the NetAudit test suite.

Environment variables MUST be set before any app imports so that
pydantic-settings picks them up before the lru_cache fires.
"""
import os
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock

# ── Env setup (must precede all app imports) ───────────────────────
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-testing-purposes-only-x")
os.environ.setdefault("ENCRYPTION_KEY", "12345678901234567890123456789012")  # exactly 32 chars
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "test")

import pytest
import pytest_asyncio
from fastapi import FastAPI
from httpx import AsyncClient, ASGITransport
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.core.limiter import limiter
from app.core.auth import hash_password
from app.db.session import get_db
from app.api.routes import auth as auth_routes
from app.models.models import (
    Organization, User, UserRole, AIProvider,
)


# ── Mock DB session ────────────────────────────────────────────────

class MockSession:
    """Thin AsyncSession stand-in that avoids any real DB connection."""

    def __init__(self, *execute_returns):
        self._results = list(execute_returns)
        self._call_index = 0
        self._pending: list = []

    def configure(self, *execute_returns):
        self._results = list(execute_returns)
        self._call_index = 0
        self._pending = []
        return self

    async def execute(self, *args, **kwargs):
        if self._call_index >= len(self._results):
            raise IndexError(
                f"MockSession.execute called more times than configured "
                f"(call #{self._call_index + 1}, only {len(self._results)} results set)"
            )
        result = self._results[self._call_index]
        self._call_index += 1
        return result

    def add(self, obj):
        self._pending.append(obj)

    async def flush(self):
        # Simulate PostgreSQL RETURNING: apply all column-level defaults that the
        # DB would normally set, so the Python object has complete data post-flush.
        from sqlalchemy import inspect as sa_inspect

        for obj in self._pending:
            try:
                mapper = sa_inspect(type(obj))
            except Exception:
                continue

            for col_attr in mapper.column_attrs:
                col = col_attr.columns[0]
                attr_name = col_attr.key

                if getattr(obj, attr_name, None) is not None:
                    continue

                if col.default is not None:
                    if col.default.is_callable:
                        try:
                            setattr(obj, attr_name, col.default.arg(None))
                        except Exception:
                            pass
                    elif col.default.is_scalar:
                        try:
                            setattr(obj, attr_name, col.default.arg)
                        except Exception:
                            pass
                elif col.server_default is not None:
                    # Server defaults (e.g. func.now()) — infer sensible values by type.
                    try:
                        pt = col.type.impl_instance.python_type if hasattr(col.type, "impl_instance") else col.type.python_type
                        if pt == bool:
                            setattr(obj, attr_name, False)
                        elif pt == datetime:
                            setattr(obj, attr_name, datetime.now(timezone.utc))
                    except (NotImplementedError, AttributeError, Exception):
                        pass

        self._pending.clear()

    async def commit(self):
        pass

    async def rollback(self):
        pass

    async def close(self):
        pass


def db_result(value=None):
    """Mock result whose scalar_one_or_none() returns value."""
    r = MagicMock()
    r.scalar_one_or_none.return_value = value
    r.scalar.return_value = value
    return r


def db_count(n: int):
    """Mock result whose scalar() returns n (for COUNT queries)."""
    r = MagicMock()
    r.scalar_one_or_none.return_value = None
    r.scalar.return_value = n
    return r


# ── Model factories ────────────────────────────────────────────────

TEST_PASSWORD = "testpass123"
_TEST_HASH = hash_password(TEST_PASSWORD)  # computed once per session


def make_org(**overrides) -> Organization:
    now = datetime.now(timezone.utc)
    fields = dict(
        id=uuid.uuid4(),
        name="Test Org",
        slug="test-org",
        created_at=now,
        ai_provider=AIProvider.OLLAMA,
        ai_api_key_encrypted=None,
        ai_model=None,
        ai_ollama_url="http://ollama:11434",
        ldap_enabled=False,
        ldap_config=None,
    )
    fields.update(overrides)
    return Organization(**fields)


def make_user(org_id=None, **overrides) -> User:
    now = datetime.now(timezone.utc)
    fields = dict(
        id=uuid.uuid4(),
        organization_id=org_id or uuid.uuid4(),
        email="admin@test.com",
        username="admin",
        hashed_password=_TEST_HASH,
        role=UserRole.IT_ADMIN,
        is_active=True,
        is_ldap_user=False,
        assigned_device_ip=None,
        agent_token_hash=None,
        created_at=now,
        last_login=None,
    )
    fields.update(overrides)
    return User(**fields)


# ── App & client fixtures ──────────────────────────────────────────

@pytest.fixture(scope="session")
def auth_app() -> FastAPI:
    app = FastAPI()
    app.include_router(auth_routes.router)
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    return app


@pytest_asyncio.fixture
async def auth_client(auth_app: FastAPI):
    """Yields an AsyncClient wired to the auth router with a fresh MockSession."""
    session = MockSession()

    async def override_get_db():
        yield session

    auth_app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=auth_app),
        base_url="http://test",
    ) as client:
        client.mock_session = session  # expose for per-test configuration
        yield client

    auth_app.dependency_overrides.clear()
