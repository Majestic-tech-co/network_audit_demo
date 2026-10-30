"""
Data retention and erasure.

purge_expired_data: deletes finished scans (and their findings and raw output files), stale
    devices and old packet captures once they pass the configured retention period.
erase_user: GDPR-style erasure. The user row is anonymized rather than deleted so scans,
    findings and audit history that reference it stay intact; everything that identifies the
    person (login, tokens, assigned IP and, optionally, their registered devices) is removed.
export_user_data: the matching access request (what we hold about one user).
"""
import os
import time
from datetime import datetime, timedelta, timezone

import structlog
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.models import (
    AgentToken, Device, Finding, Port, RefreshToken, Scan, ScanStatus, TopologyLink, User,
)

log = structlog.get_logger()

CAPTURES_DIR = "/app/scan_results/captures"
RESULTS_DIR = "/app/scan_results"
FINISHED = (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED)


def _remove_file(path: str, allowed_root: str) -> bool:
    """Delete a file, but only inside allowed_root (paths come from the database)."""
    try:
        real, root = os.path.realpath(path), os.path.realpath(allowed_root)
        if os.path.commonpath([real, root]) != root or not os.path.isfile(real):
            return False
        os.remove(real)
        return True
    except (OSError, ValueError):
        return False


def purge_old_captures(days: int, captures_dir: str = CAPTURES_DIR, now: float | None = None) -> int:
    if days <= 0 or not os.path.isdir(captures_dir):
        return 0
    cutoff = (now or time.time()) - days * 86400
    removed = 0
    for entry in os.scandir(captures_dir):
        if entry.is_file() and entry.name.endswith(".pcap") and entry.stat().st_mtime < cutoff:
            try:
                os.remove(entry.path)
                removed += 1
            except OSError:
                log.warning("capture_delete_failed", file=entry.name)
    return removed


async def _delete_devices(db: AsyncSession, device_ids) -> None:
    """Remove devices and everything that hangs off them."""
    device_ids = list(device_ids)
    if not device_ids:
        return
    await db.execute(delete(Finding).where(Finding.device_id.in_(device_ids)))
    await db.execute(delete(Port).where(Port.device_id.in_(device_ids)))
    await db.execute(delete(TopologyLink).where(or_(
        TopologyLink.source_device_id.in_(device_ids), TopologyLink.target_device_id.in_(device_ids))))
    await db.execute(update(Scan).where(Scan.device_id.in_(device_ids)).values(device_id=None))
    await db.execute(update(AgentToken).where(AgentToken.device_id.in_(device_ids)).values(device_id=None))
    await db.execute(delete(Device).where(Device.id.in_(device_ids)))


async def purge_expired_data(
    db: AsyncSession,
    *,
    scan_days: int,
    device_days: int,
    results_dir: str = RESULTS_DIR,
    now: datetime | None = None,
) -> dict:
    now = now or datetime.now(timezone.utc)
    counts = {"scans": 0, "findings": 0, "devices": 0, "raw_files": 0}

    if scan_days > 0:
        cutoff = now - timedelta(days=scan_days)
        old = (await db.execute(
            select(Scan.id, Scan.raw_output_path).where(
                Scan.status.in_(FINISHED), func.coalesce(Scan.completed_at, Scan.created_at) < cutoff)
        )).all()
        ids = [r.id for r in old]
        if ids:
            counts["findings"] = (await db.execute(delete(Finding).where(Finding.scan_id.in_(ids)))).rowcount
            counts["scans"] = (await db.execute(delete(Scan).where(Scan.id.in_(ids)))).rowcount
            await db.commit()  # rows are gone; now remove the files they pointed at
            counts["raw_files"] = sum(1 for r in old if r.raw_output_path and _remove_file(r.raw_output_path, results_dir))

    if device_days > 0:
        cutoff = now - timedelta(days=device_days)
        has_findings = select(Finding.id).where(Finding.device_id == Device.id).exists()
        stale = (await db.execute(
            select(Device.id).where(
                func.coalesce(Device.last_seen, Device.first_seen) < cutoff, ~has_findings)
        )).scalars().all()
        await _delete_devices(db, stale)
        counts["devices"] = len(stale)
        await db.commit()

    return counts


async def erase_user(db: AsyncSession, user: User, *, erase_devices: bool = True) -> dict:
    """Anonymize a user and remove their personal data. Caller must authorize and commit."""
    device_ids = []
    if erase_devices:
        device_ids = (await db.execute(
            select(Device.id).where(Device.registered_user_id == user.id))).scalars().all()
        await _delete_devices(db, device_ids)
    else:
        await db.execute(update(Device).where(Device.registered_user_id == user.id).values(registered_user_id=None))

    await db.execute(delete(AgentToken).where(AgentToken.user_id == user.id))
    await db.execute(delete(RefreshToken).where(RefreshToken.user_id == user.id))

    user.email = f"erased-{user.id}@erased.invalid"
    user.username = "Erased user"
    user.hashed_password = None
    user.agent_token_hash = None
    user.assigned_device_ip = None
    user.is_active = False
    user.is_ldap_user = False  # an erased account must not be re-provisioned/matched by LDAP sync
    user.locked_until = None
    await db.flush()
    return {"devices_deleted": len(device_ids)}


async def export_user_data(db: AsyncSession, user: User) -> dict:
    def iso(v):
        return v.isoformat() if v else None

    devices = (await db.execute(select(Device).where(Device.registered_user_id == user.id))).scalars().all()
    device_ids = [d.id for d in devices]
    findings = []
    if device_ids:
        findings = (await db.execute(select(Finding).where(Finding.device_id.in_(device_ids)))).scalars().all()
    tokens = (await db.execute(select(AgentToken).where(AgentToken.user_id == user.id))).scalars().all()
    scans = (await db.execute(select(Scan).where(Scan.initiated_by_id == user.id))).scalars().all()

    return {
        "user": {
            "id": str(user.id), "email": user.email, "username": user.username, "role": user.role.value,
            "is_active": user.is_active, "is_ldap_user": user.is_ldap_user,
            "assigned_device_ip": user.assigned_device_ip,
            "created_at": iso(user.created_at), "last_login": iso(user.last_login),
        },
        "devices": [
            {"id": str(d.id), "ip_address": d.ip_address, "mac_address": d.mac_address,
             "hostname": d.hostname, "os_guess": d.os_guess, "last_seen": iso(d.last_seen)}
            for d in devices
        ],
        "findings": [
            {"id": str(f.id), "type": f.finding_type, "severity": f.severity.value, "title": f.title,
             "file_path": f.file_path, "file_hash": f.file_hash, "created_at": iso(f.created_at)}
            for f in findings
        ],
        "agent_tokens": [{"id": str(t.id), "label": t.label, "last_used": iso(t.last_used),
                          "created_at": iso(t.created_at), "is_active": t.is_active} for t in tokens],
        "scans_initiated": [{"id": str(s.id), "type": s.scan_type.value, "target": s.target,
                             "created_at": iso(s.created_at)} for s in scans],
    }
