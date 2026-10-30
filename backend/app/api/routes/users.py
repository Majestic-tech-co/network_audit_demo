"""
Users management routes (IT Admin only for create/update).
GET    /api/users       — list org users
POST   /api/users       — create user
PATCH  /api/users/{id}  — update user
GET    /api/users/{id}/export — access request: all data held about a user
DELETE /api/users/{id}  — erasure request: anonymize user, optionally delete their devices
"""
from uuid import UUID

from fastapi import Request, APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.limiter import limiter
from app.core.refresh_tokens import revoke_all_for_user
from app.services.retention import erase_user, export_user_data
import structlog
from app.core.tenancy import get_for_org
from app.db.session import get_db
from app.models.models import User, UserRole
from app.core.auth import get_current_admin, get_current_it_user
from app.core.auth import hash_password
from app.schemas.schemas import UserResponse, CreateUserRequest, UpdateUserRequest

log = structlog.get_logger()
router = APIRouter(prefix="/api/users", tags=["users"])


@router.get("", response_model=list[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_it_user),
):
    result = await db.execute(
        select(User)
        .where(User.organization_id == current_user.organization_id)
        .order_by(User.created_at)
    )
    return [UserResponse.model_validate(u) for u in result.scalars().all()]


@router.post("", response_model=UserResponse, status_code=201)
@limiter.limit("20/minute")
async def create_user(
    request: Request,
    req: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        organization_id=current_user.organization_id,
        email=req.email,
        username=req.username,
        hashed_password=hash_password(req.password),
        role=req.role,
        assigned_device_ip=req.assigned_device_ip,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.patch("/{user_id}", response_model=UserResponse)
@limiter.limit("60/minute")
async def update_user(
    request: Request,
    user_id: UUID,
    req: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    user = await get_for_org(db, User, user_id, current_user.organization_id, name="User")

    if req.username is not None:
        user.username = req.username
    sign_out = False
    if req.role is not None:
        sign_out = sign_out or req.role != user.role
        user.role = req.role
    if req.is_active is not None:
        sign_out = sign_out or (req.is_active is False and user.is_active)
        user.is_active = req.is_active
    if sign_out:
        # Role change or deactivation ends every session; they log in again with fresh claims.
        await revoke_all_for_user(db, user.id)
    if req.assigned_device_ip is not None:
        user.assigned_device_ip = req.assigned_device_ip

    await db.flush()
    await db.refresh(user)
    return UserResponse.model_validate(user)


@router.get("/{user_id}/export")
@limiter.limit("10/minute")
async def export_user(
    request: Request,
    user_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    """Data-subject access request: everything stored about one user."""
    user = await get_for_org(db, User, user_id, current_user.organization_id, name="User")
    return await export_user_data(db, user)


@router.delete("/{user_id}", status_code=204)
@limiter.limit("10/minute")
async def erase_user_endpoint(
    request: Request,
    user_id: UUID,
    erase_devices: bool = True,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_admin),
):
    """
    Erasure request: anonymizes the account, revokes all sessions and tokens, and (by default)
    deletes the devices registered to the user along with their findings. Irreversible.
    """
    user = await get_for_org(db, User, user_id, current_user.organization_id, name="User")
    if user.id == current_user.id:
        raise HTTPException(status_code=400, detail="You cannot erase your own account")
    result = await erase_user(db, user, erase_devices=erase_devices)
    log.info("user_erased", user_id=str(user.id), by=str(current_user.id), **result)
