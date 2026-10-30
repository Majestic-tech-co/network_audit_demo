"""
Scan management routes.
POST   /api/scans          — start a scan (IT team only)
GET    /api/scans          — list scans with pagination
GET    /api/scans/{id}     — get scan details
DELETE /api/scans/{id}     — cancel a running scan
GET    /api/scans/{id}/findings — findings for a specific scan
"""
from datetime import datetime, timezone
from fastapi import Request, APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from uuid import UUID

from app.core.limiter import limiter
from app.core.tenancy import get_for_org
from app.db.session import get_db
from app.models.models import Scan, Finding, User, ScanStatus
from app.core.auth import get_current_it_writer, get_current_it_user
from app.schemas.schemas import (
    StartScanRequest, ScanResponse, ScanListResponse,
    FindingListResponse, FindingResponse
)
from app.tasks.scan_tasks import run_network_scan

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanResponse, status_code=201)
@limiter.limit("10/minute;60/hour")
async def start_scan(
    request: Request,
    req: StartScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_writer),
):
    # Check concurrent scan limit
    running = await db.execute(
        select(func.count()).select_from(Scan).where(
            Scan.organization_id == current_user.organization_id,
            Scan.status == ScanStatus.RUNNING,
        )
    )
    if running.scalar() >= 3:
        raise HTTPException(
            status_code=429,
            detail="Maximum concurrent scans (3) reached. Wait for a scan to complete."
        )

    scan = Scan(
        organization_id=current_user.organization_id,
        initiated_by_id=current_user.id,
        scan_type=req.scan_type,
        target=req.target,
        options=req.options,
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Dispatch to Celery
    task = run_network_scan.delay(str(scan.id), req.scan_type.value, req.target, req.options)
    scan.task_id = task.id
    await db.flush()

    await db.refresh(scan, ["initiated_by"])
    return ScanResponse.model_validate(scan)


@router.get("", response_model=ScanListResponse)
async def list_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    query = select(Scan).where(Scan.organization_id == current_user.organization_id)
    if status:
        query = query.where(Scan.status == status)
    query = query.order_by(desc(Scan.created_at))

    total_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(total_q)).scalar()

    query = query.offset((page - 1) * limit).limit(limit)
    result = await db.execute(query)
    scans = result.scalars().all()

    return ScanListResponse(
        items=[ScanResponse.model_validate(s) for s in scans],
        total=total,
    )


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    scan = await get_for_org(db, Scan, scan_id, current_user.organization_id, name="Scan")
    return ScanResponse.model_validate(scan)


@router.delete("/{scan_id}", status_code=204)
async def cancel_scan(
    scan_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_writer),
):
    scan = await get_for_org(db, Scan, scan_id, current_user.organization_id, name="Scan")
    if scan.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
        raise HTTPException(status_code=400, detail="Scan is not in a cancellable state")

    # Revoke Celery task
    if scan.task_id:
        from app.tasks.celery_app import celery_app
        celery_app.control.revoke(scan.task_id, terminate=True)

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(timezone.utc)


@router.get("/{scan_id}/findings", response_model=FindingListResponse)
async def scan_findings(
    scan_id: UUID,
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    # Verify scan belongs to org
    scan_result = await db.execute(
        select(Scan).where(
            Scan.id == scan_id,
            Scan.organization_id == current_user.organization_id,
        )
    )
    if not scan_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Scan not found")

    query = select(Finding).where(Finding.scan_id == scan_id)
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar()
    findings = (await db.execute(query.offset((page - 1) * limit).limit(limit))).scalars().all()

    return FindingListResponse(
        items=[FindingResponse.model_validate(f) for f in findings],
        total=total,
    )
