"""
Tenant isolation helpers.

Every organization-owned row must be fetched through `get_for_org` (or an explicit
`organization_id == user.organization_id` filter) so one organization can never read or
modify another's data. A missing row and a foreign row are indistinguishable (both 404).
"""
from typing import Any, Sequence, Type, TypeVar

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

T = TypeVar("T")


async def get_for_org(
    db: AsyncSession,
    model: Type[T],
    object_id: Any,
    org_id: Any,
    *,
    options: Sequence[Any] = (),
    name: str = "Resource",
) -> T:
    """Load `model` by id, restricted to the organization; 404 if absent or foreign."""
    stmt = select(model).where(model.id == object_id, model.organization_id == org_id)
    if options:
        stmt = stmt.options(*options)
    obj = (await db.execute(stmt)).scalar_one_or_none()
    if obj is None:
        raise HTTPException(status_code=404, detail=f"{name} not found")
    return obj
