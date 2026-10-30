"""
Topology discovery routes.
POST /api/topology/scan  — trigger LLDP discovery
GET  /api/topology/links — return stored topology links
GET  /api/topology/status — scan status from Redis
"""
import json
from fastapi import APIRouter, Depends, HTTPException
import redis.asyncio as aioredis

from app.core.auth import get_current_it_user, get_current_it_writer
from app.core.config import settings
from app.db.session import get_db
from app.models.models import User, TopologyLink, Device
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/api/topology", tags=["topology"])


async def _redis():
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        yield r
    finally:
        await r.aclose()


@router.post("/scan")
async def start_topology_scan(
    current_user: User = Depends(get_current_it_writer),
):
    """Queue an LLDP topology discovery task."""
    from app.tasks.topology_tasks import run_lldp_topology
    org_id = str(current_user.organization_id)
    run_lldp_topology.delay(org_id)
    return {"status": "queued", "org_id": org_id}


@router.get("/status")
async def topology_scan_status(
    current_user: User = Depends(get_current_it_user),
):
    """Return current LLDP scan status from Redis."""
    org_id = str(current_user.organization_id)
    r = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        raw = await r.get(f"lldp:{org_id}:status")
        if not raw:
            return {"status": "idle", "count": 0}
        return json.loads(raw)
    finally:
        await r.aclose()


@router.get("/links")
async def get_topology_links(
    current_user: User = Depends(get_current_it_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Return all stored topology links for this org.
    Each link includes the target device's id/ip/hostname and LLDP capability flags.
    """
    org_id = current_user.organization_id
    result = await db.execute(
        select(TopologyLink).where(TopologyLink.organization_id == org_id)
    )
    links = result.scalars().all()

    return {
        "links": [
            {
                "id": str(lnk.id),
                "source_device_id": str(lnk.source_device_id) if lnk.source_device_id else None,
                "target_device_id": str(lnk.target_device_id) if lnk.target_device_id else None,
                "source_port": lnk.source_port,
                "target_ip": lnk.target_ip,
                "target_hostname": lnk.target_hostname,
                "target_mac": lnk.target_mac,
                "is_bridge": lnk.is_bridge,
                "is_router": lnk.is_router,
                "is_wlan": lnk.is_wlan,
                "capabilities": lnk.capabilities,
                "link_type": lnk.link_type,
                "last_seen": lnk.last_seen.isoformat() if lnk.last_seen else None,
            }
            for lnk in links
        ]
    }
