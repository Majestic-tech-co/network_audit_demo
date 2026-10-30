"""
End-user self-service routes.
GET  /api/user/device     — my device status
POST /api/user/scan       — start a scan on my device
GET  /api/user/findings   — my device findings only
GET  /api/user/agent-token — generate / get my agent token
"""
import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from fastapi import Request, APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, case
from sqlalchemy.orm import selectinload

from app.core.limiter import limiter
from app.core.timeutil import as_utc
from app.db.session import get_db
from app.models.models import (
    User, Device, Finding, Scan, AgentToken,
    ScanType, ScanStatus, FindingStatus
)
from app.core.auth import get_current_user
from app.schemas.schemas import (
    UserDeviceResponse, StartUserScanRequest,
    UserFindingResponse, UserFindingListResponse, AgentTokenResponse
)

router = APIRouter(prefix="/api/user", tags=["user"])


async def _get_user_device(user: User, db: AsyncSession) -> Device | None:
    """Find the device this user's agent is bound to (falling back to the IT-assigned address)."""
    result = await db.execute(
        select(Device).where(
            Device.organization_id == user.organization_id,
            Device.registered_user_id == user.id,
        ).order_by(desc(Device.last_agent_checkin)).limit(1)
    )
    device = result.scalars().first()
    if device or not user.assigned_device_ip:
        return device
    result = await db.execute(
        select(Device).where(
            Device.organization_id == user.organization_id,
            Device.ip_address == user.assigned_device_ip,
        )
    )
    return result.scalar_one_or_none()


@router.get("/device", response_model=UserDeviceResponse)
async def get_my_device(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    device = await _get_user_device(current_user, db)

    if not device:
        return UserDeviceResponse(
            ip_address=current_user.assigned_device_ip,
            hostname=None,
            os_guess=None,
            agent_connected=False,
            last_agent_checkin=None,
            last_scan=None,
            risk_score=0.0,
        )

    # Check if agent is "connected" — checked in within last 2 minutes
    agent_connected = (
        device.last_agent_checkin is not None
        and (datetime.now(timezone.utc) - as_utc(device.last_agent_checkin)).total_seconds() < 120
    )

    # Last scan time for this device
    last_scan_result = await db.execute(
        select(Scan.completed_at)
        .where(
            Scan.organization_id == device.organization_id,
            Scan.device_id == device.id,
            Scan.status == ScanStatus.COMPLETED,
        )
        .order_by(desc(Scan.completed_at))
        .limit(1)
    )
    last_scan = last_scan_result.scalar_one_or_none()

    return UserDeviceResponse(
        ip_address=device.ip_address,
        hostname=device.hostname,
        os_guess=device.os_guess,
        agent_connected=agent_connected,
        last_agent_checkin=device.last_agent_checkin,
        last_scan=last_scan,
        risk_score=device.risk_score,
    )


@router.post("/scan", status_code=201)
@limiter.limit("5/minute")
async def start_my_scan(
    request: Request,
    req: StartUserScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    device = await _get_user_device(current_user, db)

    # Check agent is alive
    if not device or not device.is_agent_registered:
        raise HTTPException(
            status_code=400,
            detail="NetAudit agent is not installed on your device. Ask IT for the installer."
        )

    agent_connected = (
        device.last_agent_checkin is not None
        and (datetime.now(timezone.utc) - as_utc(device.last_agent_checkin)).total_seconds() < 120
    )
    if not agent_connected:
        raise HTTPException(
            status_code=503,
            detail="Agent is offline. Make sure the NetAudit agent is running on your computer."
        )

    # Map user-facing scan type to internal type
    scan_type_map = {
        "virus_quick": ScanType.VIRUS,
        "virus_full": ScanType.VIRUS,
        "network_device": ScanType.PORT_SCAN,
        "full_device": ScanType.FULL_DEVICE,
    }

    # One outstanding job per device: stops a user from flooding their agent with scans.
    busy = await db.execute(
        select(Scan.id).where(
            Scan.device_id == device.id,
            Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        ).limit(1)
    )
    if busy.first():
        raise HTTPException(status_code=409, detail="A scan is already queued or running on your device.")

    scan = Scan(
        organization_id=current_user.organization_id,
        initiated_by_id=current_user.id,
        scan_type=scan_type_map[req.scan_type],
        target=device.ip_address,
        device_id=device.id,
        options={"subtype": req.scan_type, "requested_by_user": True},
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.flush()

    return {"scan_id": str(scan.id), "status": "pending", "message": "Scan queued. Your agent will pick it up shortly."}


@router.get("/findings", response_model=UserFindingListResponse)
async def get_my_findings(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Returns only findings for the current user's own device."""
    device = await _get_user_device(current_user, db)
    if not device:
        return UserFindingListResponse(items=[], total=0)

    result = await db.execute(
        select(Finding)
        .where(Finding.device_id == device.id)
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
    findings = result.scalars().all()

    # End users get a subset of finding data — no raw technical details
    return UserFindingListResponse(
        items=[UserFindingResponse.model_validate(f) for f in findings],
        total=len(findings),
    )


@router.post("/agent-token/rotate", response_model=AgentTokenResponse)
@limiter.limit("5/minute")
async def rotate_agent_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Revoke the current agent token(s) and issue a new one (shown once). Keeps the device binding."""
    result = await db.execute(
        select(AgentToken).where(AgentToken.user_id == current_user.id, AgentToken.is_active == True)  # noqa: E712
    )
    old = result.scalars().all()
    device_id = next((t.device_id for t in old if t.device_id), None)
    for t in old:
        t.is_active = False

    raw_token = secrets.token_urlsafe(32)
    token = AgentToken(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        label=f"{current_user.username}'s device",
        device_id=device_id,
    )
    db.add(token)
    await db.flush()
    await db.refresh(token)
    response = AgentTokenResponse.model_validate(token)
    response.token = raw_token
    return response


@router.get("/agent-token", response_model=AgentTokenResponse)
@limiter.limit("10/minute")
async def get_or_create_agent_token(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get existing agent token or create a new one. Token shown once on creation."""
    result = await db.execute(
        select(AgentToken).where(
            AgentToken.user_id == current_user.id,
            AgentToken.is_active == True,
        ).order_by(desc(AgentToken.created_at)).limit(1)
    )
    existing = result.scalar_one_or_none()

    if existing:
        return AgentTokenResponse.model_validate(existing)

    # Generate new token
    raw_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    token = AgentToken(
        user_id=current_user.id,
        organization_id=current_user.organization_id,
        token_hash=token_hash,
        label=f"{current_user.username}'s device",
    )
    db.add(token)
    await db.flush()
    await db.refresh(token)

    response = AgentTokenResponse.model_validate(token)
    response.token = raw_token  # Only returned once
    return response
