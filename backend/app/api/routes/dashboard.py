"""
Dashboard stats route.
GET /api/dashboard/stats
"""
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db.session import get_db
from app.models.models import Device, Finding, Scan, User, Severity, FindingStatus, ScanStatus
from app.core.auth import get_current_it_user
from app.schemas.schemas import DashboardStats

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats", response_model=DashboardStats)
async def dashboard_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    org_id = current_user.organization_id
    now = datetime.now(timezone.utc)
    thirty_days_ago = now - timedelta(days=30)
    twenty_four_hours_ago = now - timedelta(hours=24)

    async def count(model, *filters):
        r = await db.execute(select(func.count()).select_from(model).where(*filters))
        return r.scalar() or 0

    total_devices = await count(Device, Device.organization_id == org_id)
    active_24h = await count(Device, Device.organization_id == org_id, Device.last_seen >= twenty_four_hours_ago)
    critical = await count(Finding, Finding.organization_id == org_id, Finding.severity == Severity.CRITICAL, Finding.status == FindingStatus.OPEN)
    high = await count(Finding, Finding.organization_id == org_id, Finding.severity == Severity.HIGH, Finding.status == FindingStatus.OPEN)
    open_findings = await count(Finding, Finding.organization_id == org_id, Finding.status.in_([FindingStatus.OPEN, FindingStatus.ACKNOWLEDGED, FindingStatus.IN_PROGRESS]))
    resolved_30d = await count(Finding, Finding.organization_id == org_id, Finding.status == FindingStatus.RESOLVED, Finding.resolved_at >= thirty_days_ago)
    virus_threats = await count(Finding, Finding.organization_id == org_id, Finding.finding_type == "virus", Finding.status != FindingStatus.RESOLVED)
    agent_devices = await count(Device, Device.organization_id == org_id, Device.is_agent_registered == True)

    # Last scan time
    last_scan_result = await db.execute(
        select(Scan.created_at)
        .where(Scan.organization_id == org_id, Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    last_scan = last_scan_result.scalar_one_or_none()

    return DashboardStats(
        total_devices=total_devices,
        active_devices_24h=active_24h,
        critical_findings=critical,
        high_findings=high,
        open_findings=open_findings,
        resolved_30d=resolved_30d,
        virus_threats=virus_threats,
        last_scan=last_scan,
        agent_registered_devices=agent_devices,
    )
