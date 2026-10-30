"""
Agent routes — called by local agents running on employee machines.
POST /api/agent/checkin          — agent heartbeat + job poll
POST /api/agent/results/{job_id} — upload scan results
POST /api/agent/results/{job_id}/error — report job failure

Trust model
-----------
An agent token belongs to exactly one user and, after its first check-in, to exactly one
Device. Everything an agent can do is scoped to that device:
  * it only receives jobs created for its own device (Scan.device_id),
  * it can only report on a RUNNING job that was dispatched to it,
  * its IP address is informational; it never identifies the device.
"""
import hashlib
import ipaddress
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.limiter import limiter, agent_token_key
from app.db.session import get_db
from app.models.models import (
    AgentToken, Device, Scan, ScanStatus, ScanType, User, UserRole,
)
from app.schemas.schemas import (
    AgentCheckinRequest, AgentCheckinResponse, AgentJob,
    AgentResultRequest, AgentErrorRequest,
)
from app.tasks.scan_tasks import process_agent_results

router = APIRouter(prefix="/api/agent", tags=["agent"])

# Server-side scan type -> job type understood by the agent.
AGENT_JOB_TYPES = {
    ScanType.VIRUS: "virus_scan",
    ScanType.PORT_SCAN: "system_audit",
    ScanType.FULL_DEVICE: "full_device",
}
IT_ROLES = {UserRole.IT_ADMIN, UserRole.IT_ENGINEER, UserRole.IT_VIEWER}


async def _authenticate_agent(
    x_agent_token: str = Header(...),
    db: AsyncSession = Depends(get_db),
) -> AgentToken:
    """Validate agent token header."""
    token_hash = hashlib.sha256(x_agent_token.encode()).hexdigest()
    result = await db.execute(
        select(AgentToken).where(
            AgentToken.token_hash == token_hash,
            AgentToken.is_active == True,  # noqa: E712
        )
    )
    token = result.scalar_one_or_none()
    if not token:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    token.last_used = datetime.now(timezone.utc)
    return token


async def _resolve_device(
    token: AgentToken, req: AgentCheckinRequest, db: AsyncSession
) -> Device:
    """Return the device bound to this token, binding or creating it on first check-in."""
    if token.device_id:
        device = (await db.execute(select(Device).where(
            Device.id == token.device_id,
            Device.organization_id == token.organization_id,
        ))).scalar_one_or_none()
        if device:
            return device
        token.device_id = None  # device was deleted; re-bind below

    owner = (await db.execute(select(User).where(User.id == token.user_id))).scalar_one_or_none()
    if owner is None or not owner.is_active:
        raise HTTPException(status_code=401, detail="Invalid agent token")

    ip = req.local_ip
    existing = (await db.execute(select(Device).where(
        Device.organization_id == token.organization_id,
        Device.ip_address == ip,
    ))).scalar_one_or_none()

    if existing is not None:
        # An address may be claimed only if it is unowned and the token's user is entitled to it:
        # IT staff (devices discovered by network scans) or the user it was assigned to.
        owned_by_other = existing.registered_user_id not in (None, token.user_id)
        entitled = owner.role in IT_ROLES or owner.assigned_device_ip == ip
        if owned_by_other or (existing.registered_user_id is None and not entitled):
            raise HTTPException(status_code=409, detail="This address is already registered to another device")
        device = existing
    else:
        if ipaddress.ip_address(ip).is_loopback or ipaddress.ip_address(ip).is_unspecified:
            raise HTTPException(status_code=400, detail="Agent could not determine a usable network address")
        device = Device(organization_id=token.organization_id, ip_address=ip)
        db.add(device)

    device.registered_user_id = token.user_id
    await db.flush()
    token.device_id = device.id
    return device


@router.post("/checkin", response_model=AgentCheckinResponse)
@limiter.limit("6/minute", key_func=agent_token_key)
async def agent_checkin(
    request: Request,
    req: AgentCheckinRequest,
    token: AgentToken = Depends(_authenticate_agent),
    db: AsyncSession = Depends(get_db),
    x_agent_version: str = Header(default="unknown", max_length=50),
):
    """Agent heartbeat. Returns any pending scan jobs for this agent's device."""
    device = await _resolve_device(token, req, db)
    now = datetime.now(timezone.utc)

    device.last_agent_checkin = now
    device.last_seen = now
    device.agent_version = x_agent_version
    device.is_agent_registered = True
    if req.system_info.get("hostname"):
        device.hostname = str(req.system_info["hostname"])[:255]
    if req.system_info.get("os"):
        device.os_guess = f"{req.system_info.get('os')} {req.system_info.get('os_release', '')}".strip()[:255]

    # The address may change (DHCP); follow it unless another device already holds it.
    if device.ip_address != req.local_ip and not ipaddress.ip_address(req.local_ip).is_loopback:
        taken = (await db.execute(select(Device.id).where(
            Device.organization_id == token.organization_id,
            Device.ip_address == req.local_ip,
        ))).first()
        if not taken:
            device.ip_address = req.local_ip

    pending = (await db.execute(select(Scan).where(
        Scan.organization_id == token.organization_id,
        Scan.device_id == device.id,
        Scan.status == ScanStatus.PENDING,
    ).order_by(Scan.created_at).limit(3))).scalars().all()

    jobs = []
    for scan in pending:
        job_type = AGENT_JOB_TYPES.get(scan.scan_type)
        if job_type is None:
            scan.status = ScanStatus.FAILED
            scan.error_message = "Scan type is not supported by agents"
            scan.completed_at = now
            continue
        options = dict(scan.options or {})
        options["quick"] = options.get("subtype") != "virus_full"
        jobs.append(AgentJob(id=str(scan.id), type=job_type, options=options))
        scan.status = ScanStatus.RUNNING
        scan.started_at = now

    return AgentCheckinResponse(pending_jobs=jobs)


async def _get_dispatched_scan(job_id: str, token: AgentToken, db: AsyncSession) -> Scan:
    """The scan must be RUNNING and dispatched to *this token's device*; otherwise 404."""
    try:
        scan_uuid = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan = (await db.execute(select(Scan).where(
        Scan.id == scan_uuid,
        Scan.organization_id == token.organization_id,
        Scan.device_id == token.device_id,
        Scan.status == ScanStatus.RUNNING,
    ))).scalar_one_or_none()
    if token.device_id is None or scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.post("/results/{job_id}", status_code=200)
@limiter.limit("30/minute", key_func=agent_token_key)
async def upload_results(
    request: Request,
    job_id: str,
    req: AgentResultRequest,
    token: AgentToken = Depends(_authenticate_agent),
    db: AsyncSession = Depends(get_db),
):
    """Agent uploads scan results. The job stays RUNNING until the worker has processed them."""
    scan = await _get_dispatched_scan(job_id, token, db)
    await db.commit()  # release the row before queueing so the worker sees a consistent state
    process_agent_results.delay(str(scan.id), req.type, req.results)
    return {"status": "received"}


@router.post("/results/{job_id}/error", status_code=200)
@limiter.limit("30/minute", key_func=agent_token_key)
async def report_error(
    request: Request,
    job_id: str,
    req: AgentErrorRequest,
    token: AgentToken = Depends(_authenticate_agent),
    db: AsyncSession = Depends(get_db),
):
    scan = await _get_dispatched_scan(job_id, token, db)
    scan.status = ScanStatus.FAILED
    scan.error_message = req.error[:500]
    scan.completed_at = datetime.now(timezone.utc)
    return {"status": "recorded"}
