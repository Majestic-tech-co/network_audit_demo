"""
Celery task: LLDP topology discovery.
Runs a 35-second passive Scapy capture, matches results to known devices,
and persists TopologyLink records.
"""
import asyncio
import json
import redis as sync_redis
import structlog

from app.tasks.celery_app import celery_app
from app.core.config import settings

log = structlog.get_logger()


@celery_app.task(name="run_lldp_topology", bind=True, max_retries=0)
def run_lldp_topology(self, org_id: str):
    log.info("lldp_task_start", org_id=org_id)
    _set_status(org_id, "running", 0)
    try:
        count = asyncio.run(_lldp_async(org_id))
        _set_status(org_id, "done", count)
        log.info("lldp_task_done", org_id=org_id, links=count)
    except Exception as exc:
        log.error("lldp_task_failed", org_id=org_id, error=str(exc))
        _set_status(org_id, "failed", 0)
        raise


async def _lldp_async(org_id: str) -> int:
    from sqlalchemy import select
    from sqlalchemy import delete as sa_delete
    from app.db.session import AsyncSessionLocal
    from app.models.models import Device, TopologyLink
    from app.services.lldp_service import LLDPService

    # ── Fetch known devices ──────────────────────────────────────
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(Device).where(Device.organization_id == org_id))
        devices = res.scalars().all()
        devices_plain = [
            {"id": str(d.id), "ip_address": d.ip_address, "hostname": d.hostname}
            for d in devices
        ]

    # ── Discover interface from Redis ────────────────────────────
    r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        raw = r.get("capture:host:interfaces")
        interfaces = json.loads(raw) if raw else []
        interface = interfaces[0] if interfaces else "eth0"
    finally:
        r.close()

    # ── Run LLDP capture (blocking, 35 s) ───────────────────────
    service = LLDPService()
    neighbors = service.discover_neighbors(interface, timeout=35)

    if not neighbors:
        log.warning("lldp_no_frames", interface=interface)
        return 0

    # ── Match to known devices ───────────────────────────────────
    neighbors = service.match_to_devices(neighbors, devices_plain)

    # ── Persist (replace previous LLDP links for this org) ───────
    async with AsyncSessionLocal() as db:
        await db.execute(
            sa_delete(TopologyLink).where(
                TopologyLink.organization_id == org_id,
                TopologyLink.link_type == "lldp",
            )
        )
        for nb in neighbors:
            db.add(TopologyLink(
                organization_id=org_id,
                source_device_id=None,
                target_device_id=nb.get("target_device_id"),
                source_port=nb.get("remote_port"),
                target_ip=nb.get("remote_ip"),
                target_hostname=nb.get("remote_hostname"),
                target_mac=nb.get("remote_mac") or nb.get("source_mac"),
                capabilities=nb.get("capabilities", {}),
                is_bridge=nb.get("is_bridge", False),
                is_router=nb.get("is_router", False),
                is_wlan=nb.get("is_wlan", False),
                link_type="lldp",
                raw_data={k: v for k, v in nb.items() if k != "target_device_id"},
            ))
        await db.commit()

    return len(neighbors)


def _set_status(org_id: str, status: str, count: int):
    r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        r.setex(
            f"lldp:{org_id}:status",
            3600,
            json.dumps({"status": status, "count": count}),
        )
    finally:
        r.close()
