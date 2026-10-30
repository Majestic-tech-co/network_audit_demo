"""
Device routes.
GET /api/devices          — list all discovered devices
GET /api/devices/{id}     — device detail
GET /api/devices/{id}/findings — findings for device
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, case
from sqlalchemy.orm import selectinload
from uuid import UUID

from app.core.tenancy import get_for_org
from app.db.session import get_db
from app.models.models import Device, Finding, User, FindingStatus, Severity
from app.core.auth import get_current_it_user
from app.schemas.schemas import DeviceResponse, DeviceListResponse, FindingListResponse, FindingResponse

router = APIRouter(prefix="/api/devices", tags=["devices"])


@router.get("", response_model=DeviceListResponse)
async def list_devices(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    query = (
        select(Device)
        .where(Device.organization_id == current_user.organization_id)
        .options(selectinload(Device.ports))
        .order_by(desc(Device.risk_score), desc(Device.last_seen))
    )

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar()
    devices = (await db.execute(query.offset((page - 1) * limit).limit(limit))).scalars().all()

    # Attach open findings count
    device_list = []
    for device in devices:
        d = DeviceResponse.model_validate(device)
        count_result = await db.execute(
            select(func.count()).select_from(Finding).where(
                Finding.device_id == device.id,
                Finding.status.in_(["open", "acknowledged", "in_progress"]),
            )
        )
        d.open_findings_count = count_result.scalar()
        device_list.append(d)

    return DeviceListResponse(items=device_list, total=total)


@router.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    device = await get_for_org(db, Device, device_id, current_user.organization_id, options=[selectinload(Device.ports)], name="Device")
    return DeviceResponse.model_validate(device)


@router.get("/{device_id}/findings", response_model=FindingListResponse)
async def device_findings(
    device_id: UUID,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    # Verify device belongs to org
    device_result = await db.execute(
        select(Device).where(
            Device.id == device_id,
            Device.organization_id == current_user.organization_id,
        )
    )
    if not device_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Device not found")

    query = (
        select(Finding)
        .where(Finding.device_id == device_id)
        .options(
            selectinload(Finding.device).selectinload(Device.ports),
            selectinload(Finding.assigned_to),
        )
        .order_by(
            case(
                (Finding.severity == "critical", 0),
                (Finding.severity == "high", 1),
                (Finding.severity == "medium", 2),
                (Finding.severity == "low", 3),
                else_=4,
            ),
            desc(Finding.created_at)
        )
    )
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar()
    findings = (await db.execute(query.offset((page - 1) * limit).limit(limit))).scalars().all()

    return FindingListResponse(
        items=[FindingResponse.model_validate(f) for f in findings],
        total=total,
    )
