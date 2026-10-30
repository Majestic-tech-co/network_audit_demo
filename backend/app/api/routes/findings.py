"""
Findings routes.
GET    /api/findings              — list all findings (IT team)
GET    /api/findings/{id}         — get finding detail
PATCH  /api/findings/{id}         — update status, assign, add notes
POST   /api/findings/{id}/remediate — generate AI remediation
"""
from datetime import datetime, timezone
from fastapi import Request, APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, case
from sqlalchemy.orm import selectinload
from uuid import UUID

from app.core.limiter import limiter
from app.core.tenancy import get_for_org
from app.db.session import get_db
from app.models.models import Finding, Device, User, FindingStatus
from app.core.auth import get_current_it_user, get_current_it_writer
from app.schemas.schemas import (
    FindingResponse, FindingListResponse, UpdateFindingRequest
)
from app.tasks.scan_tasks import generate_ai_remediation

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=FindingListResponse)
async def list_findings(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    status: str = Query(None),
    severity: str = Query(None),
    device_id: UUID = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    query = (
        select(Finding)
        .where(Finding.organization_id == current_user.organization_id)
        .options(
            selectinload(Finding.device).selectinload(Device.ports),
            selectinload(Finding.assigned_to),
        )
        .order_by(
            # Explicit severity sort order: critical > high > medium > low > info
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

    if status:
        query = query.where(Finding.status == status)
    if severity:
        query = query.where(Finding.severity == severity)
    if device_id:
        query = query.where(Finding.device_id == device_id)

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar()
    findings = (await db.execute(query.offset((page - 1) * limit).limit(limit))).scalars().all()

    return FindingListResponse(
        items=[FindingResponse.model_validate(f) for f in findings],
        total=total,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    finding = await get_for_org(db, Finding, finding_id, current_user.organization_id, options=[selectinload(Finding.device).selectinload(Device.ports), selectinload(Finding.assigned_to)], name="Finding")
    return FindingResponse.model_validate(finding)


@router.patch("/{finding_id}", response_model=FindingResponse)
async def update_finding(
    finding_id: UUID,
    req: UpdateFindingRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_writer),
):
    finding = await get_for_org(db, Finding, finding_id, current_user.organization_id, options=[selectinload(Finding.device).selectinload(Device.ports), selectinload(Finding.assigned_to)], name="Finding")

    if req.status is not None:
        finding.status = req.status
        if req.status == FindingStatus.RESOLVED:
            finding.resolved_at = datetime.now(timezone.utc)
    if req.assigned_to_id is not None:
        # Verify assignee is in same org
        assignee = await db.execute(
            select(User).where(
                User.id == req.assigned_to_id,
                User.organization_id == current_user.organization_id,
            )
        )
        if not assignee.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Assignee not found in organization")
        finding.assigned_to_id = req.assigned_to_id
    if req.notes is not None:
        finding.notes = req.notes

    await db.flush()
    await db.refresh(finding)
    return FindingResponse.model_validate(finding)


@router.post("/{finding_id}/remediate", response_model=FindingResponse)
@limiter.limit("10/minute;100/hour")
async def trigger_remediation(
    request: Request,
    finding_id: UUID,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_writer),
):
    """Trigger async AI remediation generation for a finding."""
    finding = await get_for_org(db, Finding, finding_id, current_user.organization_id, options=[selectinload(Finding.device)], name="Finding")

    # Dispatch to Celery (non-blocking)
    generate_ai_remediation.delay(str(finding_id), str(current_user.organization_id))

    return FindingResponse.model_validate(finding)
