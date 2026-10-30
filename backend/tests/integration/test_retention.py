"""Retention purge, user erasure and data export."""
import os
import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.models.models import (
    AgentToken, Device, Finding, FindingStatus, Port, RefreshToken, Scan, ScanStatus, ScanType, Severity, User,
)
from app.services.retention import purge_expired_data, purge_old_captures
from tests.integration.conftest import PASSWORD, bearer

NOW = datetime.now(timezone.utc)


def _scan(org, status, days_old, **kw):
    t = NOW - timedelta(days=days_old)
    return Scan(organization_id=org.id, scan_type=ScanType.PORT_SCAN, target="10.0.0.0/24", status=status,
                created_at=t, completed_at=t, **kw)


def _finding(org, scan, device=None):
    return Finding(organization_id=org.id, scan_id=scan.id, device_id=device.id if device else None,
                   finding_type="open_port", severity=Severity.LOW, status=FindingStatus.OPEN,
                   title="t", description="d")


# ── purge ─────────────────────────────────────────────────────────

async def test_purge_removes_only_old_finished_scans(session_factory, world, tmp_path):
    raw = tmp_path / "old.xml"
    raw.write_text("<nmaprun/>")
    keep_raw = tmp_path / "keep.xml"
    keep_raw.write_text("<nmaprun/>")
    async with session_factory() as db:
        old = _scan(world.org_a, ScanStatus.COMPLETED, 400, raw_output_path=str(raw))
        recent = _scan(world.org_a, ScanStatus.COMPLETED, 10, raw_output_path=str(keep_raw))
        old_running = _scan(world.org_a, ScanStatus.RUNNING, 400)
        db.add_all([old, recent, old_running])
        await db.flush()
        db.add_all([_finding(world.org_a, old), _finding(world.org_a, recent)])
        await db.commit()
        ids = (old.id, recent.id, old_running.id)

        counts = await purge_expired_data(db, scan_days=180, device_days=0, results_dir=str(tmp_path))

        remaining = set((await db.execute(select(Scan.id))).scalars())
    assert ids[0] not in remaining and ids[1] in remaining and ids[2] in remaining  # running scans are never purged
    assert counts["scans"] >= 1 and counts["findings"] == 1
    assert not raw.exists() and keep_raw.exists()


async def test_purge_never_deletes_files_outside_results_dir(session_factory, world, tmp_path):
    outside = tmp_path / "outside" / "secret.txt"
    outside.parent.mkdir()
    outside.write_text("do not delete")
    results = tmp_path / "results"
    results.mkdir()
    async with session_factory() as db:
        db.add(_scan(world.org_a, ScanStatus.COMPLETED, 400, raw_output_path=str(outside)))
        await db.commit()
        await purge_expired_data(db, scan_days=180, device_days=0, results_dir=str(results))
    assert outside.exists()


async def test_purge_disabled_with_zero(session_factory, world):
    async with session_factory() as db:
        s = _scan(world.org_a, ScanStatus.COMPLETED, 4000)
        db.add(s)
        await db.commit()
        counts = await purge_expired_data(db, scan_days=0, device_days=0)
        assert counts == {"scans": 0, "findings": 0, "devices": 0, "raw_files": 0}
        assert (await db.get(Scan, s.id)) is not None


async def test_purge_stale_devices_keeps_ones_with_findings(session_factory, world):
    async with session_factory() as db:
        old = NOW - timedelta(days=500)
        stale = Device(organization_id=world.org_a.id, ip_address="10.1.1.1", last_seen=old)
        with_finding = Device(organization_id=world.org_a.id, ip_address="10.1.1.2", last_seen=old)
        fresh = Device(organization_id=world.org_a.id, ip_address="10.1.1.3", last_seen=NOW)
        db.add_all([stale, with_finding, fresh])
        await db.flush()
        db.add(Port(device_id=stale.id, port_number=22))
        recent_scan = _scan(world.org_a, ScanStatus.COMPLETED, 1)
        db.add(recent_scan)
        await db.flush()
        db.add(_finding(world.org_a, recent_scan, with_finding))
        await db.commit()

        counts = await purge_expired_data(db, scan_days=0, device_days=365)
        ids = set((await db.execute(select(Device.id))).scalars())
    assert counts["devices"] >= 1
    assert stale.id not in ids and with_finding.id in ids and fresh.id in ids


def test_purge_old_captures(tmp_path):
    old, new, other = tmp_path / "a.pcap", tmp_path / "b.pcap", tmp_path / "keep.txt"
    for f in (old, new, other):
        f.write_text("x")
    ten_days_ago = time.time() - 10 * 86400
    os.utime(old, (ten_days_ago, ten_days_ago))
    os.utime(other, (ten_days_ago, ten_days_ago))
    assert purge_old_captures(7, str(tmp_path)) == 1
    assert not old.exists() and new.exists() and other.exists()
    assert purge_old_captures(0, str(tmp_path)) == 0


# ── erasure + export ──────────────────────────────────────────────

async def _victim_with_data(session_factory, world):
    async with session_factory() as db:
        victim = User(organization_id=world.org_a.id, email="victim@example.com", username="Vic Tim",
                      hashed_password="x", role=world.users.end_user.role, assigned_device_ip="10.2.2.2",
                      agent_token_hash="h")
        db.add(victim)
        await db.flush()
        dev = Device(organization_id=world.org_a.id, ip_address="10.2.2.2", hostname="vic-laptop",
                     registered_user_id=victim.id)
        db.add(dev)
        await db.flush()
        scan = _scan(world.org_a, ScanStatus.COMPLETED, 1)
        db.add(scan)
        await db.flush()
        db.add_all([_finding(world.org_a, scan, dev), Port(device_id=dev.id, port_number=80),
                    AgentToken(user_id=victim.id, organization_id=world.org_a.id, token_hash=uuid.uuid4().hex,
                               device_id=dev.id, label="Vic's laptop"),
                    RefreshToken(user_id=victim.id, family_id=uuid.uuid4(),
                                 expires_at=NOW + timedelta(days=1))])
        await db.commit()
        return victim.id, dev.id


async def test_erase_user_anonymizes_and_removes_personal_data(client, world, session_factory):
    victim_id, dev_id = await _victim_with_data(session_factory, world)
    r = await client.delete(f"/api/users/{victim_id}", headers=bearer(world.users.admin))
    assert r.status_code == 204
    async with session_factory() as db:
        u = await db.get(User, victim_id)
        assert u is not None and not u.is_active
        assert "victim" not in u.email and u.username == "Erased user"
        assert u.hashed_password is None and u.assigned_device_ip is None and u.agent_token_hash is None
        assert await db.get(Device, dev_id) is None
        assert not (await db.execute(select(Finding).where(Finding.device_id == dev_id))).scalars().all()
        assert not (await db.execute(select(AgentToken).where(AgentToken.user_id == victim_id))).scalars().all()
        assert not (await db.execute(select(RefreshToken).where(RefreshToken.user_id == victim_id))).scalars().all()


async def test_erase_user_can_keep_devices(client, world, session_factory):
    victim_id, dev_id = await _victim_with_data(session_factory, world)
    r = await client.delete(f"/api/users/{victim_id}?erase_devices=false", headers=bearer(world.users.admin))
    assert r.status_code == 204
    async with session_factory() as db:
        dev = await db.get(Device, dev_id)
        assert dev is not None and dev.registered_user_id is None


async def test_erased_user_cannot_log_in(client, world, session_factory):
    victim_id, _ = await _victim_with_data(session_factory, world)
    async with session_factory() as db:
        email = (await db.get(User, victim_id)).email
    await client.delete(f"/api/users/{victim_id}", headers=bearer(world.users.admin))
    r = await client.post("/api/auth/login", data={"username": email, "password": PASSWORD})
    assert r.status_code == 401


async def test_erase_guards(client, world):
    admin = world.users.admin
    own = await client.delete(f"/api/users/{admin.id}", headers=bearer(admin))
    assert own.status_code == 400  # an admin cannot erase their own account
    foreign = await client.delete(f"/api/users/{world.users.b_admin.id}", headers=bearer(admin))
    assert foreign.status_code == 404  # another organization's user looks nonexistent


async def test_erase_and_export_require_admin(client, world):
    for who in (world.users.engineer, world.users.viewer, world.users.end_user):
        assert (await client.delete(f"/api/users/{world.users.viewer.id}", headers=bearer(who))).status_code == 403
        assert (await client.get(f"/api/users/{world.users.viewer.id}/export", headers=bearer(who))).status_code == 403
    assert (await client.delete(f"/api/users/{world.users.viewer.id}")).status_code == 401


async def test_export_contains_user_data_and_no_secrets(client, world, session_factory):
    victim_id, dev_id = await _victim_with_data(session_factory, world)
    r = await client.get(f"/api/users/{victim_id}/export", headers=bearer(world.users.admin))
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["email"] == "victim@example.com"
    assert body["devices"][0]["hostname"] == "vic-laptop"
    assert len(body["findings"]) == 1 and len(body["agent_tokens"]) == 1
    text = r.text
    assert "hashed_password" not in text and "token_hash" not in text and "agent_token_hash" not in text


async def test_export_is_tenant_isolated(client, world):
    r = await client.get(f"/api/users/{world.users.b_admin.id}/export", headers=bearer(world.users.admin))
    assert r.status_code == 404
