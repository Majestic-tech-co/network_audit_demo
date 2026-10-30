"""
Database session factory.
Uses SQLAlchemy async engine with connection pooling.
"""
import os
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from app.core.config import settings

# Celery workers set this env var so we use NullPool (no shared connections across processes)
_is_worker = os.environ.get("NETAUDIT_WORKER", "false").lower() == "true"

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_pre_ping=True,
    poolclass=NullPool if _is_worker else None,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncSession:
    """FastAPI dependency — yields a database session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def check_schema() -> None:
    """
    Refuse to start against a database that has not been migrated to the code's schema.
    Tables are created ONLY by Alembic (`alembic upgrade head`, run by the `migrate` service),
    never implicitly by the application.
    """
    from pathlib import Path

    from alembic.config import Config
    from alembic.script import ScriptDirectory
    from sqlalchemy import text

    ini = Path(__file__).resolve().parents[2] / "alembic.ini"
    cfg = Config(str(ini))
    cfg.set_main_option("script_location", str(ini.parent / "migrations"))  # independent of the CWD
    head = ScriptDirectory.from_config(cfg).get_current_head()

    try:
        async with engine.connect() as conn:
            current = (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar()
    except Exception:
        current = None
    if current != head:
        raise RuntimeError(
            f"Database schema is not up to date (database: {current or 'none'}, expected: {head}). "
            "Run `alembic upgrade head` (docker compose runs it via the 'migrate' service)."
        )
