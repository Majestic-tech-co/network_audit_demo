"""
Celery Beat periodic tasks.

run_scheduled_scans: fires every minute, checks ScheduledScan table,
launches any scans whose next_run is due.
"""
import asyncio
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, delete
from croniter import croniter
import structlog

from app.tasks.celery_app import celery_app
from app.db.session import AsyncSessionLocal
from app.models.models import ScheduledScan, Scan, ScanStatus, RefreshToken

log = structlog.get_logger()


# Register with Celery Beat — fires every 60 seconds
celery_app.conf.beat_schedule = {
    "run-scheduled-scans": {
        "task": "run_scheduled_scans",
        "schedule": 60.0,  # every minute
    },
    "reap-stale-agent-scans": {
        "task": "reap_stale_agent_scans",
        "schedule": 300.0,
    },
    "purge-old-data": {
        "task": "purge_old_data",
        "schedule": 86400.0,
    },
    "purge-expired-refresh-tokens": {
        "task": "purge_expired_refresh_tokens",
        "schedule": 86400.0,
    },
}


@celery_app.task(name="run_scheduled_scans")
def run_scheduled_scans():
    asyncio.run(_run_scheduled_scans_async())


async def _run_scheduled_scans_async():
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ScheduledScan).where(
                ScheduledScan.is_active == True,
                ScheduledScan.next_run <= now,
            )
        )
        schedules = result.scalars().all()

        for schedule in schedules:
            log.info("firing_scheduled_scan", schedule_id=str(schedule.id), name=schedule.name)

            # Create a Scan record
            scan = Scan(
                organization_id=schedule.organization_id,
                initiated_by_id=schedule.created_by_id,
                scan_type=schedule.scan_type,
                target=schedule.target,
                options=schedule.options or {},
                status=ScanStatus.PENDING,
            )
            db.add(scan)
            await db.flush()

            # Dispatch to worker
            from app.tasks.scan_tasks import run_network_scan
            task = run_network_scan.delay(
                str(scan.id),
                schedule.scan_type.value,
                schedule.target,
                schedule.options or {},
            )
            scan.task_id = task.id

            # Update schedule timestamps
            schedule.last_run = now
            try:
                schedule.next_run = croniter(schedule.cron_expression, now).get_next(datetime)
            except Exception:
                schedule.is_active = False
                log.error("invalid_cron_disabling_schedule", schedule_id=str(schedule.id))

        await db.commit()
        if schedules:
            log.info("scheduled_scans_fired", count=len(schedules))


AGENT_JOB_TIMEOUT = timedelta(hours=2)
AGENT_PENDING_TIMEOUT = timedelta(hours=24)


@celery_app.task(name="reap_stale_agent_scans")
def reap_stale_agent_scans():
    asyncio.run(_reap_stale_agent_scans_async())


async def _reap_stale_agent_scans_async():
    """Fail agent jobs that were never picked up or never reported back, so none hangs forever."""
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        stale = (await db.execute(
            select(Scan).where(
                Scan.device_id.is_not(None),
                (
                    ((Scan.status == ScanStatus.RUNNING) & (Scan.started_at < now - AGENT_JOB_TIMEOUT))
                    | ((Scan.status == ScanStatus.PENDING) & (Scan.created_at < now - AGENT_PENDING_TIMEOUT))
                ),
            )
        )).scalars().all()
        for scan in stale:
            scan.status = ScanStatus.FAILED
            scan.error_message = "The agent did not complete this scan in time."
            scan.completed_at = now
        if stale:
            await db.commit()
            log.info("stale_agent_scans_failed", count=len(stale))


@celery_app.task(name="purge_expired_refresh_tokens")
def purge_expired_refresh_tokens():
    asyncio.run(_purge_expired_refresh_tokens_async())


async def _purge_expired_refresh_tokens_async():
    """Expired tokens can't be used (or replayed meaningfully), so the rows are just clutter."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            delete(RefreshToken).where(RefreshToken.expires_at < datetime.now(timezone.utc))
        )
        await db.commit()
        log.info("expired_refresh_tokens_purged", count=result.rowcount)


@celery_app.task(name="purge_old_data")
def purge_old_data():
    asyncio.run(_purge_old_data_async())


async def _purge_old_data_async():
    """Apply the RETENTION_* settings (0 disables a rule)."""
    from app.core.config import settings
    from app.services.retention import purge_expired_data, purge_old_captures

    async with AsyncSessionLocal() as db:
        counts = await purge_expired_data(
            db, scan_days=settings.RETENTION_SCAN_DAYS, device_days=settings.RETENTION_DEVICE_DAYS)
    counts["captures"] = purge_old_captures(settings.RETENTION_CAPTURE_DAYS)
    log.info("retention_purge_done", **counts)
