"""
Integration fixtures: the real FastAPI app (app.main) on a real (SQLite) database.

Unlike the mocked-session unit tests, these exercise routing, dependencies, role checks,
tenant scoping and SQL together, so authorization regressions actually fail a test.
"""
import uuid
from types import SimpleNamespace

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import StaticPool

from app.core.auth import create_access_token, hash_password
from app.core.limiter import limiter
from app.db.session import get_db
from app.main import app
from app.models.models import (
    Base, Device, Finding, FindingStatus, Organization, ScheduledScan, Scan, ScanStatus,
    ScanType, Severity, User, UserRole,
)

PASSWORD = "correct-horse-battery"
_PASSWORD_HASH = hash_password(PASSWORD)  # bcrypt is slow; hash once per test session


@pytest_asyncio.fixture
async def session_factory():
    engine = create_async_engine(
        "sqlite+aiosqlite://", poolclass=StaticPool, connect_args={"check_same_thread": False}
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    await engine.dispose()


@pytest_asyncio.fixture
async def client(session_factory, monkeypatch):
    # Same commit/rollback semantics as the production get_db dependency.
    async def override_get_db():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db
    limiter.enabled = False

    # Never talk to Celery/Redis from tests.
    fake_delay = lambda *a, **k: SimpleNamespace(id="task-id")  # noqa: E731
    from app.tasks import scan_tasks, capture_tasks, topology_tasks
    for task in (scan_tasks.run_network_scan, scan_tasks.process_agent_results,
                 scan_tasks.generate_ai_remediation, capture_tasks.run_capture,
                 topology_tasks.run_lldp_topology):
        monkeypatch.setattr(task, "delay", fake_delay)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c

    app.dependency_overrides.clear()
    limiter.enabled = True


def bearer(user: User) -> dict:
    token = create_access_token({"sub": str(user.id), "org": str(user.organization_id), "role": user.role})
    return {"Authorization": f"Bearer {token}"}


async def _make_org(db, name):
    org = Organization(name=name, slug=f"{name.lower()}-{uuid.uuid4().hex[:6]}")
    db.add(org)
    await db.flush()
    return org


async def _make_user(db, org, role, label):
    user = User(
        organization_id=org.id, email=f"{label}-{uuid.uuid4().hex[:6]}@{org.slug}.test",
        username=label, hashed_password=_PASSWORD_HASH, role=role, is_active=True,
    )
    db.add(user)
    await db.flush()
    return user


@pytest_asyncio.fixture
async def world(session_factory):
    """Two organizations. Org A has one user per role; org B owns the 'foreign' resources."""
    async with session_factory() as db:
        a, b = await _make_org(db, "OrgA"), await _make_org(db, "OrgB")
        users = SimpleNamespace(
            admin=await _make_user(db, a, UserRole.IT_ADMIN, "admin"),
            engineer=await _make_user(db, a, UserRole.IT_ENGINEER, "engineer"),
            viewer=await _make_user(db, a, UserRole.IT_VIEWER, "viewer"),
            end_user=await _make_user(db, a, UserRole.END_USER, "enduser"),
            b_admin=await _make_user(db, b, UserRole.IT_ADMIN, "badmin"),
        )
        b_device = Device(organization_id=b.id, ip_address="10.9.9.9", hostname="b-host")
        db.add(b_device)
        await db.flush()
        b_scan = Scan(organization_id=b.id, scan_type=ScanType.PORT_SCAN, target="10.9.9.0/24",
                      status=ScanStatus.COMPLETED)
        db.add(b_scan)
        await db.flush()
        b_finding = Finding(organization_id=b.id, scan_id=b_scan.id, device_id=b_device.id,
                            finding_type="open_port", severity=Severity.HIGH, status=FindingStatus.OPEN,
                            title="B finding", description="secret to org B")
        b_sched = ScheduledScan(organization_id=b.id, name="b-sched", scan_type=ScanType.PORT_SCAN,
                                target="10.9.9.0/24", cron_expression="0 * * * *",
                                created_by_id=users.b_admin.id)
        db.add_all([b_finding, b_sched])
        await db.commit()
        foreign = SimpleNamespace(device=b_device, scan=b_scan, finding=b_finding, schedule=b_sched)
    return SimpleNamespace(org_a=a, org_b=b, users=users, foreign=foreign)
