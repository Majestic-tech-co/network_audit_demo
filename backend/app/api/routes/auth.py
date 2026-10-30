"""
Authentication routes.
POST /api/auth/register  — create account (+ org on first user)
POST /api/auth/login     — local OR LDAP login (auto-detected)
POST /api/auth/refresh   — rotate refresh token, issue new access token
POST /api/auth/logout    — revoke the session
GET  /api/auth/me        — current user info
"""
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import asyncio
import re
import uuid

from app.db.session import get_db
from app.models.models import User, Organization, UserRole
from app.core.auth import (
    hash_password, verify_password,
    create_access_token,
    get_current_user,
)
from app.core.refresh_tokens import issue_refresh_token, rotate_refresh_token, logout as revoke_session
from app.core.config import settings
from app.schemas.schemas import (
    RegisterRequest, TokenResponse, RefreshRequest, UserResponse
)
from app.services.ldap_service import ldap_service_from_org, LDAPUserInfo
import jwt
from jwt import PyJWTError as JWTError
import structlog

from app.core.limiter import limiter
from app.core.timeutil import as_utc
from app.core.turnstile import verify_turnstile

log = structlog.get_logger()
router = APIRouter(prefix="/api/auth", tags=["auth"])

MAX_FAILED_LOGINS = 5
LOCKOUT_DURATION = timedelta(minutes=15)
_DUMMY_HASH = hash_password("netaudit-dummy-password")


@router.get("/login-config")
async def login_config(db: AsyncSession = Depends(get_db)):
    """Public endpoint — tells the login page whether LDAP is enabled."""
    result = await db.execute(
        select(Organization).where(Organization.ldap_enabled == True).limit(1)
    )
    ldap_org = result.scalar_one_or_none()
    return {"ldap_enabled": ldap_org is not None}


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug[:50] or "org"


# ─── Register ─────────────────────────────────────────────────────

@router.post("/register", response_model=TokenResponse, status_code=201, dependencies=[Depends(verify_turnstile)])
@limiter.limit("5/minute")
async def register(request: Request, req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    # Check closure first so a closed instance never reveals which emails exist.
    user_count = await db.execute(select(func.count()).select_from(User))
    is_first_user = user_count.scalar() == 0

    if is_first_user:
        existing = await db.execute(select(User).where(User.email == req.email))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Email already registered")

    if is_first_user:
        org_name = req.organization_name or f"{req.username}'s Organization"
        base_slug = _slugify(org_name)
        slug = base_slug
        suffix = 1
        while True:
            exists = await db.execute(select(Organization).where(Organization.slug == slug))
            if not exists.scalar_one_or_none():
                break
            slug = f"{base_slug}-{suffix}"
            suffix += 1
        org = Organization(name=org_name, slug=slug)
        db.add(org)
        await db.flush()
        role = UserRole.IT_ADMIN
    else:
        # Self-registration is only for bootstrapping the first admin.
        # Further accounts are created by an IT Admin (POST /api/users) or LDAP.
        raise HTTPException(
            status_code=403,
            detail="Registration is closed. Ask your IT administrator for an account.",
        )

    user = User(
        organization_id=org.id,
        email=req.email,
        username=req.username,
        hashed_password=hash_password(req.password),
        role=role,
    )
    db.add(user)
    await db.flush()

    token_data = {"sub": str(user.id), "org": str(org.id), "role": role}
    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=await issue_refresh_token(db, user),
        user=UserResponse.model_validate(user),
    )


# ─── Login ────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse, dependencies=[Depends(verify_turnstile)])
@limiter.limit("10/minute")
async def login(
    request: Request,
    form: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    """
    Login flow:
      1. Look up the user by email
      2. If org has LDAP enabled AND user is LDAP user (or not found locally):
           → Try LDAP authentication
           → Auto-provision user on first LDAP login
      3. Otherwise: local password check
    """
    # Find existing user record
    result = await db.execute(select(User).where(User.email == form.username))
    user = result.scalar_one_or_none()

    # Load org (need it to check LDAP config)
    org = None
    if user:
        org_result = await db.execute(
            select(Organization).where(Organization.id == user.organization_id)
        )
        org = org_result.scalar_one_or_none()
    else:
        # No local user — check if any org has LDAP enabled that might know this user
        org_result = await db.execute(
            select(Organization).where(Organization.ldap_enabled == True).limit(1)
        )
        org = org_result.scalar_one_or_none()

    # Decide: try LDAP?
    should_try_ldap = (
        org is not None
        and org.ldap_enabled
        and (user is None or user.is_ldap_user)
    )

    if should_try_ldap:
        ldap_result = await _ldap_login(
            form.username, form.password, org, user, db
        )
        if ldap_result is not None:
            return ldap_result
        # LDAP returned None means bad credentials — fall through to give
        # a consistent error message (don't reveal whether LDAP is enabled)

    # Local authentication
    now = datetime.now(timezone.utc)
    bad_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Incorrect email or password",
        headers={"WWW-Authenticate": "Bearer"},
    )

    locked_until = as_utc(user.locked_until) if user else None
    if locked_until is not None and locked_until > now:
        raise HTTPException(
            status_code=429,
            detail="Too many failed attempts. Try again later.",
            headers={"Retry-After": str(int((locked_until - now).total_seconds()) + 1)},
        )

    if not user or not user.hashed_password:
        # Burn the same bcrypt time as a real check so response timing
        # doesn't reveal whether the email exists.
        verify_password(form.password, _DUMMY_HASH)
        raise bad_credentials
    if not verify_password(form.password, user.hashed_password):
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= MAX_FAILED_LOGINS:
            user.locked_until = now + LOCKOUT_DURATION
            user.failed_login_attempts = 0
            log.warning("account_locked", user_id=str(user.id))
        # get_db rolls back when an exception propagates, so persist the counter first
        await db.commit()
        raise bad_credentials
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = now
    token_data = {"sub": str(user.id), "org": str(user.organization_id), "role": user.role}
    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=await issue_refresh_token(db, user),
        user=UserResponse.model_validate(user),
    )


async def _ldap_login(
    email_or_username: str,
    password: str,
    org: Organization,
    existing_user: User | None,
    db: AsyncSession,
) -> TokenResponse | None:
    """
    Try to authenticate against LDAP. Returns a TokenResponse on success,
    None if credentials are wrong, raises on server error.
    """
    ldap_svc = ldap_service_from_org(org)
    if not ldap_svc:
        return None

    # Extract just the username part from email if needed
    username = email_or_username.split("@")[0] if "@" in email_or_username else email_or_username

    try:
        # Run blocking ldap3 in thread pool
        ldap_info: LDAPUserInfo | None = await asyncio.get_event_loop().run_in_executor(
            None, ldap_svc.authenticate, username, password
        )
    except Exception as e:
        log.error("ldap_server_error_during_login", error=str(e))
        # If LDAP server is down, fall through to local auth
        return None

    if ldap_info is None:
        return None  # Bad credentials

    # Auto-provision or update local user record
    user = await _provision_ldap_user(ldap_info, org, existing_user, db)
    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    user.last_login = datetime.now(timezone.utc)
    token_data = {"sub": str(user.id), "org": str(org.id), "role": user.role}
    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=await issue_refresh_token(db, user),
        user=UserResponse.model_validate(user),
    )


async def _provision_ldap_user(
    ldap_info: LDAPUserInfo,
    org: Organization,
    existing_user: User | None,
    db: AsyncSession,
) -> User:
    """
    Create a new local user record for an LDAP user on first login,
    or sync their role/name if they already exist.
    """
    if existing_user and existing_user.is_ldap_user:
        # Sync attributes from LDAP — role may have changed via AD group membership
        existing_user.username = ldap_info.display_name
        existing_user.role = ldap_info.role
        await db.flush()
        log.info("ldap_user_synced", user_id=str(existing_user.id), role=str(ldap_info.role))
        return existing_user

    if existing_user:
        # Existing local user — don't overwrite their role, just return
        return existing_user

    # First LDAP login — create user record
    user = User(
        organization_id=org.id,
        email=ldap_info.email,
        username=ldap_info.display_name,
        hashed_password=None,       # LDAP users have no local password
        role=ldap_info.role,
        is_ldap_user=True,
        is_active=True,
    )
    db.add(user)
    await db.flush()
    log.info(
        "ldap_user_provisioned",
        user_id=str(user.id),
        role=str(ldap_info.role),
    )
    return user


# ─── Refresh ──────────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("20/minute")
async def refresh(request: Request, req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    # Single use: the presented token is revoked and replaced; reuse of an old one kills the family.
    user, new_refresh = await rotate_refresh_token(db, req.refresh_token)
    token_data = {"sub": str(user.id), "org": str(user.organization_id), "role": user.role}
    return TokenResponse(
        access_token=create_access_token(token_data),
        refresh_token=new_refresh,
        user=UserResponse.model_validate(user),
    )


@router.post("/logout", status_code=204)
@limiter.limit("20/minute")
async def logout(request: Request, req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    """Revoke the session behind a refresh token. Always 204, so it can't be used to probe tokens."""
    await revoke_session(db, req.refresh_token)


# ─── Me ───────────────────────────────────────────────────────────

@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)):
    return UserResponse.model_validate(current_user)
