"""
Server-side refresh-token tracking: rotation, reuse detection and revocation.

Every refresh token carries a `jti` (its row id) and a `fam` (family id, shared by all tokens
descended from one login). A refresh token is single use: refreshing revokes it and issues a
successor in the same family. Presenting an already-used token outside a short grace window
means it was copied, so the whole family is revoked and the real user must log in again.
"""
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from jwt import PyJWTError as JWTError
from fastapi import HTTPException
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.timeutil import as_utc
from app.models.models import RefreshToken, User

# Two browser tabs refreshing at the same moment present the same token; the loser is told to
# retry (401) but is not treated as theft.
REUSE_GRACE = timedelta(seconds=10)

_INVALID = "Invalid or expired refresh token"


def _unauthorized(detail: str = _INVALID) -> HTTPException:
    return HTTPException(status_code=401, detail=detail)


async def issue_refresh_token(db: AsyncSession, user: User, family_id: uuid.UUID | None = None) -> str:
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    row = RefreshToken(
        id=uuid.uuid4(),
        user_id=user.id,
        family_id=family_id or uuid.uuid4(),
        expires_at=expires,
    )
    db.add(row)
    await db.flush()
    claims = {
        "sub": str(user.id), "org": str(user.organization_id), "role": user.role,
        "jti": str(row.id), "fam": str(row.family_id),
        "type": "refresh", "exp": expires,
    }
    return jwt.encode(claims, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _decode(token: str) -> tuple[uuid.UUID, uuid.UUID]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "refresh":
            raise _unauthorized()
        return uuid.UUID(str(payload["jti"])), uuid.UUID(str(payload["fam"]))
    except (JWTError, KeyError, ValueError):
        raise _unauthorized()


async def revoke_family(db: AsyncSession, family_id: uuid.UUID) -> None:
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )


async def revoke_all_for_user(db: AsyncSession, user_id: uuid.UUID) -> None:
    """Sign a user out everywhere (password change, deactivation, role change)."""
    await db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )


async def rotate_refresh_token(db: AsyncSession, token: str) -> tuple[User, str]:
    """Validate and consume a refresh token. Returns the user and the successor token."""
    jti, family_id = _decode(token)
    now = datetime.now(timezone.utc)

    row = (await db.execute(select(RefreshToken).where(RefreshToken.id == jti))).scalar_one_or_none()
    if row is None or row.family_id != family_id:
        raise _unauthorized()

    if row.revoked_at is not None:
        if now - as_utc(row.revoked_at) > REUSE_GRACE:
            await revoke_family(db, family_id)
            await db.commit()  # get_db rolls back on exceptions; persist the revocation first
        raise _unauthorized()

    if as_utc(row.expires_at) <= now:
        raise _unauthorized()

    user = (await db.execute(select(User).where(User.id == row.user_id))).scalar_one_or_none()
    if not user or not user.is_active:
        raise _unauthorized("User not found or disabled")

    # Atomic single use: only one concurrent request can flip revoked_at from NULL.
    claimed = await db.execute(
        update(RefreshToken)
        .where(RefreshToken.id == jti, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    if claimed.rowcount != 1:
        raise _unauthorized()

    return user, await issue_refresh_token(db, user, family_id)


async def logout(db: AsyncSession, token: str) -> None:
    """Revoke the family of the presented refresh token. Unknown/invalid tokens are a no-op."""
    try:
        _, family_id = _decode(token)
    except HTTPException:
        return
    await revoke_family(db, family_id)
