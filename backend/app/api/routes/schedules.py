"""
Scheduled scan routes.
GET    /api/schedules        — list schedules
POST   /api/schedules        — create schedule
PATCH  /api/schedules/{id}   — update / toggle active
DELETE /api/schedules/{id}   — delete schedule
"""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from croniter import croniter
from uuid import UUID

from app.core.tenancy import get_for_org
from app.db.session import get_db
from app.models.models import ScheduledScan, User
from app.core.auth import get_current_it_writer, get_current_it_user
from app.schemas.schemas import (
    CreateScheduledScanRequest, ScheduledScanResponse
)

router = APIRouter(prefix="/api/schedules", tags=["schedules"])


def _next_run(cron_expr: str) -> datetime:
    """Calculate next run time from a cron expression."""
    try:
        return croniter(cron_expr, datetime.now(timezone.utc)).get_next(datetime)
    except Exception:
        return datetime.now(timezone.utc)


@router.get("", response_model=list[ScheduledScanResponse])
async def list_schedules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    result = await db.execute(
        select(ScheduledScan).where(
            ScheduledScan.organization_id == current_user.organization_id
        ).order_by(ScheduledScan.created_at)
    )
    return [ScheduledScanResponse.model_validate(s) for s in result.scalars().all()]


@router.post("", response_model=ScheduledScanResponse, status_code=201)
async def create_schedule(
    req: CreateScheduledScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_writer),
):
    # Validate cron expression
    try:
        croniter(req.cron_expression)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid cron expression")

    schedule = ScheduledScan(
        organization_id=current_user.organization_id,
        created_by_id=current_user.id,
        name=req.name,
        scan_type=req.scan_type,
        target=req.target,
        options=req.options,
        cron_expression=req.cron_expression,
        next_run=_next_run(req.cron_expression),
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)
    return ScheduledScanResponse.model_validate(schedule)


@router.patch("/{schedule_id}", response_model=ScheduledScanResponse)
async def update_schedule(
    schedule_id: UUID,
    is_active: bool,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_writer),
):
    schedule = await get_for_org(db, ScheduledScan, schedule_id, current_user.organization_id, name="Schedule")
    schedule.is_active = is_active
    await db.flush()
    return ScheduledScanResponse.model_validate(schedule)


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(
    schedule_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_writer),
):
    schedule = await get_for_org(db, ScheduledScan, schedule_id, current_user.organization_id, name="Schedule")
    await db.delete(schedule)
