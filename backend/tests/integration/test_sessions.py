"""Refresh-token lifecycle: single use, reuse detection, logout, and revocation on user changes."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from app.core.refresh_tokens import REUSE_GRACE
from app.models.models import RefreshToken
from tests.integration.conftest import PASSWORD, bearer


async def _login(client, user):
    r = await client.post("/api/auth/login", data={"username": user.email, "password": PASSWORD})
    assert r.status_code == 200
    return r.json()


async def _refresh(client, token):
    return await client.post("/api/auth/refresh", json={"refresh_token": token})


async def _age_revocations(session_factory, seconds):
    """Pretend tokens were revoked `seconds` ago (to step outside the reuse grace window)."""
    async with session_factory() as db:
        await db.execute(
            update(RefreshToken)
            .where(RefreshToken.revoked_at.is_not(None))
            .values(revoked_at=datetime.now(timezone.utc) - timedelta(seconds=seconds))
        )
        await db.commit()


async def test_refresh_rotates_and_works(client, world):
    first = (await _login(client, world.users.admin))["refresh_token"]
    r = await _refresh(client, first)
    assert r.status_code == 200
    second = r.json()["refresh_token"]
    assert second != first
    assert (await _refresh(client, second)).status_code == 200


async def test_refresh_token_is_single_use_within_grace(client, world):
    first = (await _login(client, world.users.admin))["refresh_token"]
    assert (await _refresh(client, first)).status_code == 200
    # An immediate second use (e.g. two tabs) is refused but does not log everyone out.
    assert (await _refresh(client, first)).status_code == 401


async def test_reuse_after_grace_revokes_the_whole_family(client, world, session_factory):
    first = (await _login(client, world.users.admin))["refresh_token"]
    second = (await _refresh(client, first)).json()["refresh_token"]

    await _age_revocations(session_factory, REUSE_GRACE.total_seconds() + 5)

    assert (await _refresh(client, first)).status_code == 401  # replayed (stolen) token
    assert (await _refresh(client, second)).status_code == 401  # legitimate successor is cut off too


async def test_grace_reuse_does_not_revoke_family(client, world):
    first = (await _login(client, world.users.admin))["refresh_token"]
    second = (await _refresh(client, first)).json()["refresh_token"]
    assert (await _refresh(client, first)).status_code == 401
    assert (await _refresh(client, second)).status_code == 200


async def test_logout_revokes_session(client, world):
    tokens = await _login(client, world.users.admin)
    out = await client.post("/api/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert out.status_code == 204
    assert (await _refresh(client, tokens["refresh_token"])).status_code == 401


async def test_logout_revokes_rotated_successor(client, world):
    first = (await _login(client, world.users.admin))["refresh_token"]
    second = (await _refresh(client, first)).json()["refresh_token"]
    await client.post("/api/auth/logout", json={"refresh_token": second})
    assert (await _refresh(client, second)).status_code == 401


async def test_logout_with_garbage_is_a_quiet_204(client):
    r = await client.post("/api/auth/logout", json={"refresh_token": "not.a.token"})
    assert r.status_code == 204


async def test_logout_only_ends_that_session(client, world):
    a = (await _login(client, world.users.admin))["refresh_token"]
    b = (await _login(client, world.users.admin))["refresh_token"]
    await client.post("/api/auth/logout", json={"refresh_token": a})
    assert (await _refresh(client, b)).status_code == 200


async def test_deactivating_user_revokes_sessions(client, world):
    victim = world.users.engineer
    token = (await _login(client, victim))["refresh_token"]
    r = await client.patch(f"/api/users/{victim.id}", json={"is_active": False}, headers=bearer(world.users.admin))
    assert r.status_code == 200
    assert (await _refresh(client, token)).status_code == 401


async def test_role_change_revokes_sessions(client, world):
    victim = world.users.viewer
    token = (await _login(client, victim))["refresh_token"]
    r = await client.patch(f"/api/users/{victim.id}", json={"role": "it_engineer"}, headers=bearer(world.users.admin))
    assert r.status_code == 200
    assert (await _refresh(client, token)).status_code == 401


async def test_untracked_but_validly_signed_refresh_token_is_rejected(client, world):
    """A forged/legacy token with no database row must not be accepted."""
    import uuid
    import jwt
    from app.core.config import settings

    forged = jwt.encode(
        {"sub": str(world.users.admin.id), "type": "refresh", "jti": str(uuid.uuid4()), "fam": str(uuid.uuid4()),
         "exp": datetime.now(timezone.utc) + timedelta(days=1)},
        settings.SECRET_KEY, algorithm=settings.ALGORITHM,
    )
    assert (await _refresh(client, forged)).status_code == 401
