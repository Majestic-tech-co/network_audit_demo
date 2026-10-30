"""Agent protocol: device-bound tokens, job dispatch, result processing, rotation."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from app.models.models import (
    Device, Finding, FindingStatus, Scan, ScanStatus, ScanType, Severity, User, UserRole,
)
from app.core.auth import hash_password
from tests.integration.conftest import PASSWORD, bearer

SYSINFO = {"hostname": "laptop-1", "os": "Linux", "os_release": "6.1"}


async def new_token(client, user) -> str:
    r = await client.get("/api/user/agent-token", headers=bearer(user))
    assert r.status_code == 200
    token = r.json()["token"]
    assert token, "raw token must be returned on creation"
    return token


def agent(token):
    return {"X-Agent-Token": token}


async def checkin(client, token, ip="10.5.5.5"):
    return await client.post("/api/agent/checkin", headers=agent(token),
                             json={"system_info": SYSINFO, "local_ip": ip})


@pytest.fixture
def patched_worker(session_factory, monkeypatch):
    """Point the Celery task code at the test database."""
    from app.tasks import scan_tasks, scheduled_tasks
    monkeypatch.setattr(scan_tasks, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(scheduled_tasks, "AsyncSessionLocal", session_factory)
    return scan_tasks, scheduled_tasks


async def scan_for(client, user, scan_type="virus_quick"):
    r = await client.post("/api/user/scan", json={"scan_type": scan_type}, headers=bearer(user))
    assert r.status_code == 201, r.text
    return r.json()["scan_id"]


# ── Binding ────────────────────────────────────────────────────────

async def test_checkin_creates_and_binds_device(client, world, session_factory):
    token = await new_token(client, world.users.end_user)
    r = await checkin(client, token)
    assert r.status_code == 200 and r.json()["pending_jobs"] == []

    async with session_factory() as db:
        dev = (await db.execute(select(Device).where(Device.ip_address == "10.5.5.5"))).scalar_one()
        assert dev.registered_user_id == world.users.end_user.id
        assert dev.organization_id == world.org_a.id and dev.is_agent_registered

    # the end user can see their own device through the dashboard endpoint
    me = await client.get("/api/user/device", headers=bearer(world.users.end_user))
    assert me.json()["agent_connected"] is True


async def test_device_follows_its_token_when_ip_changes(client, world, session_factory):
    token = await new_token(client, world.users.end_user)
    await checkin(client, token, "10.5.5.5")
    await checkin(client, token, "10.5.5.77")
    async with session_factory() as db:
        devices = (await db.execute(select(Device).where(Device.registered_user_id == world.users.end_user.id))).scalars().all()
    assert len(devices) == 1 and devices[0].ip_address == "10.5.5.77"


async def test_second_user_cannot_take_over_an_address(client, world, session_factory):
    t1 = await new_token(client, world.users.end_user)
    await checkin(client, t1, "10.5.5.5")

    async with session_factory() as db:
        other = User(organization_id=world.org_a.id, email="other@example.com", username="other",
                     hashed_password=hash_password(PASSWORD), role=UserRole.END_USER, is_active=True)
        db.add(other)
        await db.commit()
        await db.refresh(other)
    t2 = await new_token(client, other)
    r = await checkin(client, t2, "10.5.5.5")
    assert r.status_code == 409


async def test_end_user_cannot_claim_discovered_device_but_it_staff_can(client, world, session_factory):
    async with session_factory() as db:
        db.add(Device(organization_id=world.org_a.id, ip_address="10.7.7.7", hostname="discovered"))
        await db.commit()
    eu = await new_token(client, world.users.end_user)
    assert (await checkin(client, eu, "10.7.7.7")).status_code == 409
    eng = await new_token(client, world.users.engineer)
    assert (await checkin(client, eng, "10.7.7.7")).status_code == 200


async def test_end_user_can_claim_their_assigned_address(client, world, session_factory):
    async with session_factory() as db:
        db.add(Device(organization_id=world.org_a.id, ip_address="10.8.8.8"))
        user = (await db.execute(select(User).where(User.id == world.users.end_user.id))).scalar_one()
        user.assigned_device_ip = "10.8.8.8"
        await db.commit()
    token = await new_token(client, world.users.end_user)
    assert (await checkin(client, token, "10.8.8.8")).status_code == 200


async def test_loopback_address_is_rejected(client, world):
    token = await new_token(client, world.users.end_user)
    assert (await checkin(client, token, "127.0.0.1")).status_code == 400


async def test_invalid_token_and_disabled_owner(client, world, session_factory):
    assert (await checkin(client, "not-a-real-token")).status_code == 401
    token = await new_token(client, world.users.end_user)
    async with session_factory() as db:
        u = (await db.execute(select(User).where(User.id == world.users.end_user.id))).scalar_one()
        u.is_active = False
        await db.commit()
    assert (await checkin(client, token)).status_code == 401


# ── Jobs ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("subtype,job_type,quick", [
    ("virus_quick", "virus_scan", True),
    ("virus_full", "virus_scan", False),
    ("network_device", "system_audit", True),
    ("full_device", "full_device", True),
])
async def test_job_types_match_what_the_agent_understands(client, world, subtype, job_type, quick):
    token = await new_token(client, world.users.end_user)
    await checkin(client, token)
    scan_id = await scan_for(client, world.users.end_user, subtype)
    jobs = (await checkin(client, token)).json()["pending_jobs"]
    assert [j["id"] for j in jobs] == [scan_id]
    assert jobs[0]["type"] == job_type
    assert jobs[0]["options"]["quick"] is quick
    # a job is handed out exactly once
    assert (await checkin(client, token)).json()["pending_jobs"] == []


async def test_user_scan_requires_connected_agent_and_blocks_flooding(client, world):
    r = await client.post("/api/user/scan", json={"scan_type": "virus_quick"}, headers=bearer(world.users.end_user))
    assert r.status_code == 400  # no agent yet
    token = await new_token(client, world.users.end_user)
    await checkin(client, token)
    await scan_for(client, world.users.end_user)
    again = await client.post("/api/user/scan", json={"scan_type": "virus_quick"}, headers=bearer(world.users.end_user))
    assert again.status_code == 409


async def test_agent_only_receives_jobs_for_its_own_device(client, world, session_factory):
    t1 = await new_token(client, world.users.end_user)
    await checkin(client, t1, "10.5.5.5")
    await scan_for(client, world.users.end_user)

    t2 = await new_token(client, world.users.engineer)
    jobs = (await checkin(client, t2, "10.6.6.6")).json()["pending_jobs"]
    assert jobs == []


# ── Results ────────────────────────────────────────────────────────

VIRUS_RESULT = {"type": "virus_scan", "results": {
    "infected_files": [{"path": "/tmp/evil.exe", "virus_name": "Win.Trojan.Test", "sha256": "ab" * 32}],
    "scan_stats": {"scanned": 1},
}}


async def test_results_flow_creates_findings_and_completes_scan(client, world, patched_worker, session_factory):
    scan_tasks, _ = patched_worker
    token = await new_token(client, world.users.end_user)
    await checkin(client, token)
    scan_id = await scan_for(client, world.users.end_user)
    await checkin(client, token)  # dispatch -> RUNNING

    r = await client.post(f"/api/agent/results/{scan_id}", headers=agent(token), json=VIRUS_RESULT)
    assert r.status_code == 200
    await scan_tasks._process_agent_results_async(scan_id, "virus_scan", VIRUS_RESULT["results"])

    findings = (await client.get("/api/user/findings", headers=bearer(world.users.end_user))).json()
    assert findings["total"] == 1 and findings["items"][0]["severity"] == "critical"
    # end users get a trimmed view of findings
    assert "assigned_to" not in findings["items"][0] and "device" not in findings["items"][0]

    async with session_factory() as db:
        scan = (await db.execute(select(Scan).where(Scan.target == "10.5.5.5"))).scalar_one()
        assert scan.status == ScanStatus.COMPLETED and scan.findings_count == 1

    # replay after completion is refused
    again = await client.post(f"/api/agent/results/{scan_id}", headers=agent(token), json=VIRUS_RESULT)
    assert again.status_code == 404


async def test_agent_cannot_report_on_another_devices_scan(client, world):
    t1 = await new_token(client, world.users.end_user)
    await checkin(client, t1, "10.5.5.5")
    scan_id = await scan_for(client, world.users.end_user)
    await checkin(client, t1, "10.5.5.5")  # running on device 1

    t2 = await new_token(client, world.users.engineer)
    await checkin(client, t2, "10.6.6.6")
    r = await client.post(f"/api/agent/results/{scan_id}", headers=agent(t2), json=VIRUS_RESULT)
    assert r.status_code == 404
    r = await client.post(f"/api/agent/results/{scan_id}/error", headers=agent(t2), json={"error": "x"})
    assert r.status_code == 404


async def test_pending_scan_cannot_be_completed_by_agent(client, world):
    token = await new_token(client, world.users.end_user)
    await checkin(client, token)
    scan_id = await scan_for(client, world.users.end_user)  # PENDING, never dispatched
    r = await client.post(f"/api/agent/results/{scan_id}", headers=agent(token), json=VIRUS_RESULT)
    assert r.status_code == 404


async def test_agent_cannot_touch_other_organizations(client, world, session_factory):
    token = await new_token(client, world.users.end_user)
    await checkin(client, token)
    r = await client.post(f"/api/agent/results/{world.foreign.scan.id}", headers=agent(token), json=VIRUS_RESULT)
    assert r.status_code == 404


async def test_agent_results_never_wipe_network_scan_findings(client, world, patched_worker, session_factory):
    scan_tasks, _ = patched_worker
    token = await new_token(client, world.users.end_user)
    await checkin(client, token)
    async with session_factory() as db:
        dev = (await db.execute(select(Device).where(Device.ip_address == "10.5.5.5"))).scalar_one()
        nmap_scan = Scan(organization_id=world.org_a.id, scan_type=ScanType.PORT_SCAN, target="10.5.5.5")
        db.add(nmap_scan)
        await db.flush()
        db.add(Finding(organization_id=world.org_a.id, scan_id=nmap_scan.id, device_id=dev.id,
                       finding_type="open_port", severity=Severity.HIGH, status=FindingStatus.OPEN,
                       title="Port 23 open", description="telnet"))
        await db.commit()

    scan_id = await scan_for(client, world.users.end_user)
    await checkin(client, token)
    await scan_tasks._process_agent_results_async(scan_id, "virus_scan", VIRUS_RESULT["results"])

    async with session_factory() as db:
        types = {f.finding_type for f in (await db.execute(select(Finding).where(Finding.device_id == dev.id))).scalars()}
    assert types == {"open_port", "virus"}


async def test_missing_clamav_is_not_reported_as_clean(client, world, patched_worker, session_factory):
    scan_tasks, _ = patched_worker
    token = await new_token(client, world.users.end_user)
    await checkin(client, token)

    # first a real detection
    s1 = await scan_for(client, world.users.end_user)
    await checkin(client, token)
    await scan_tasks._process_agent_results_async(s1, "virus_scan", VIRUS_RESULT["results"])

    # then a "scan" where ClamAV is not installed
    s2 = await scan_for(client, world.users.end_user)
    await checkin(client, token)
    await scan_tasks._process_agent_results_async(
        s2, "virus_scan", {"error": "ClamAV not installed", "infected_files": []})

    async with session_factory() as db:
        scan2 = (await db.execute(select(Scan).where(Scan.id == uuid.UUID(s2)))).scalar_one()
        assert scan2.status == ScanStatus.FAILED and "ClamAV" in scan2.error_message
        assert len((await db.execute(select(Finding).where(Finding.finding_type == "virus"))).scalars().all()) == 1


async def test_agent_error_report_fails_the_scan(client, world, session_factory):
    token = await new_token(client, world.users.end_user)
    await checkin(client, token)
    scan_id = await scan_for(client, world.users.end_user)
    await checkin(client, token)
    r = await client.post(f"/api/agent/results/{scan_id}/error", headers=agent(token), json={"error": "boom"})
    assert r.status_code == 200
    async with session_factory() as db:
        scan = (await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))).scalar_one()
    assert scan.status == ScanStatus.FAILED


async def test_oversized_agent_payload_rejected(client, world):
    token = await new_token(client, world.users.end_user)
    r = await client.post("/api/agent/checkin", headers=agent(token),
                          json={"system_info": {"x": "a" * 30000}, "local_ip": "10.5.5.5"})
    assert r.status_code == 422


# ── Maintenance ────────────────────────────────────────────────────

async def test_stale_agent_scans_are_reaped(client, world, patched_worker, session_factory):
    _, scheduled = patched_worker
    token = await new_token(client, world.users.end_user)
    await checkin(client, token)
    scan_id = await scan_for(client, world.users.end_user)
    await checkin(client, token)  # RUNNING
    async with session_factory() as db:
        scan = (await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))).scalar_one()
        scan.started_at = datetime.now(timezone.utc) - timedelta(hours=3)
        await db.commit()

    await scheduled._reap_stale_agent_scans_async()
    async with session_factory() as db:
        scan = (await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))).scalar_one()
    assert scan.status == ScanStatus.FAILED


# ── Token lifecycle ────────────────────────────────────────────────

async def test_token_rotation_revokes_old_and_keeps_device(client, world, session_factory):
    old = await new_token(client, world.users.end_user)
    await checkin(client, old)

    r = await client.post("/api/user/agent-token/rotate", headers=bearer(world.users.end_user))
    assert r.status_code == 200
    new = r.json()["token"]
    assert new and new != old

    assert (await checkin(client, old)).status_code == 401
    assert (await checkin(client, new)).status_code == 200
    async with session_factory() as db:
        count = len((await db.execute(select(Device).where(Device.registered_user_id == world.users.end_user.id))).scalars().all())
    assert count == 1  # the new token re-used the existing device


async def test_raw_token_is_not_stored(client, world, session_factory):
    from app.models.models import AgentToken
    raw = await new_token(client, world.users.end_user)
    async with session_factory() as db:
        stored = (await db.execute(select(AgentToken))).scalars().all()
    assert all(raw not in (t.token_hash or "") for t in stored)
