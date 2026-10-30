"""
Packet capture routes.
GET  /api/capture/interfaces          — list host network interfaces
POST /api/capture/start               — start a capture session
POST /api/capture/{session_id}/stop   — stop a running capture
GET  /api/capture/{session_id}/status — session status and stats
GET  /api/capture/{session_id}/export — download .pcap file
WS   /ws/capture/{session_id}         — stream live packets
"""
import asyncio
import json
import re
import uuid
from typing import Optional

import redis.asyncio as aioredis
from fastapi import Request, APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import FileResponse
import jwt
from jwt import PyJWTError as JWTError
from pydantic import BaseModel
from sqlalchemy import select

from app.core.auth import get_current_it_user, get_current_it_writer, WRITE_ROLES
from app.core.config import settings
from app.core.limiter import limiter
from app.db.session import AsyncSessionLocal
from app.models.models import User
from app.tasks.capture_tasks import run_capture

CAPTURES_DIR = "/app/scan_results/captures"

_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_BPF_RE = re.compile(r"^[A-Za-z0-9 .:/()!&|<>=\[\]-]{0,256}$")

router = APIRouter(prefix="/api/capture", tags=["capture"])
ws_router = APIRouter(tags=["capture"])


# ─── Schemas ─────────────────────────────────────────────────────

class StartCaptureRequest(BaseModel):
    interface: str
    bpf_filter: str = ""
    max_packets: int = 5000


class CaptureStatusResponse(BaseModel):
    session_id: str
    status: str
    packet_count: int
    interface: str
    bpf_filter: str
    error: Optional[str] = None


# ─── Helper ──────────────────────────────────────────────────────

async def _get_redis() -> aioredis.Redis:
    return aioredis.from_url(settings.REDIS_URL, decode_responses=True)


def _valid_session_id(session_id: str) -> str:
    """Session ids are server-generated UUIDs; reject anything else (also blocks path tricks)."""
    try:
        return str(uuid.UUID(session_id))
    except ValueError:
        raise HTTPException(status_code=404, detail="Capture session not found")


async def _session_info_for_org(r: aioredis.Redis, session_id: str, org_id) -> dict:
    """Load session info; missing and foreign-org sessions look identical (404)."""
    raw = await r.get(f"capture:{session_id}:info")
    info = json.loads(raw) if raw else None
    if not info or info.get("org_id") != str(org_id):
        raise HTTPException(status_code=404, detail="Capture session not found")
    return info


# ─── REST endpoints ──────────────────────────────────────────────

@router.get("/interfaces")
async def list_interfaces(
    current_user: User = Depends(get_current_it_user),
):
    """Return available host network interfaces registered by the worker."""
    r = await _get_redis()
    try:
        raw = await r.get("capture:host:interfaces")
        if raw:
            return {"interfaces": json.loads(raw)}
        return {"interfaces": ["eth0", "ens3", "ens18", "wlan0", "enp0s3"]}
    finally:
        await r.aclose()


@router.post("/start")
@limiter.limit("10/minute")
async def start_capture(
    request: Request,
    req: StartCaptureRequest,
    current_user: User = Depends(get_current_it_writer),
):
    """Start a new packet capture session on the given interface."""
    if not req.interface or not _IFACE_RE.match(req.interface):
        raise HTTPException(status_code=400, detail="Invalid interface name")
    if not _BPF_RE.match(req.bpf_filter or ""):
        raise HTTPException(status_code=400, detail="Invalid BPF filter")
    if not (100 <= req.max_packets <= 10000):
        raise HTTPException(status_code=400, detail="max_packets must be between 100 and 10000")

    session_id = str(uuid.uuid4())

    r = await _get_redis()
    try:
        raw_ifaces = await r.get("capture:host:interfaces")
        if raw_ifaces and req.interface not in json.loads(raw_ifaces):
            raise HTTPException(status_code=400, detail="Unknown interface")
        info = {
            "interface": req.interface,
            "bpf_filter": req.bpf_filter,
            "max_packets": req.max_packets,
            "org_id": str(current_user.organization_id),
        }
        await r.setex(f"capture:{session_id}:info", 7200, json.dumps(info))
        await r.setex(f"capture:{session_id}:status", 7200, "running")
        await r.setex(f"capture:{session_id}:count", 7200, "0")
    finally:
        await r.aclose()

    task = run_capture.delay(session_id, req.interface, req.bpf_filter, req.max_packets)

    r2 = await _get_redis()
    try:
        await r2.setex(f"capture:{session_id}:task_id", 7200, task.id)
    finally:
        await r2.aclose()

    return {"session_id": session_id}


@router.post("/{session_id}/stop")
async def stop_capture(
    session_id: str,
    current_user: User = Depends(get_current_it_writer),
):
    """Signal the capture task to stop."""
    session_id = _valid_session_id(session_id)
    r = await _get_redis()
    try:
        await _session_info_for_org(r, session_id, current_user.organization_id)
        await r.set(f"capture:{session_id}:status", "stopped")
    finally:
        await r.aclose()
    return {"status": "stopped"}


@router.get("/{session_id}/status", response_model=CaptureStatusResponse)
async def capture_status(
    session_id: str,
    current_user: User = Depends(get_current_it_user),
):
    """Get current status and packet count for a session."""
    session_id = _valid_session_id(session_id)
    r = await _get_redis()
    try:
        info = await _session_info_for_org(r, session_id, current_user.organization_id)
        status = await r.get(f"capture:{session_id}:status") or "unknown"
        count_raw = await r.get(f"capture:{session_id}:count") or "0"
        error = await r.get(f"capture:{session_id}:error")
    finally:
        await r.aclose()

    return CaptureStatusResponse(
        session_id=session_id,
        status=status,
        packet_count=int(count_raw),
        interface=info.get("interface", ""),
        bpf_filter=info.get("bpf_filter", ""),
        error=error,
    )


@router.get("/{session_id}/export")
async def export_pcap(
    session_id: str,
    current_user: User = Depends(get_current_it_writer),
):
    """Download the captured packets as a .pcap file."""
    import os
    session_id = _valid_session_id(session_id)
    r = await _get_redis()
    try:
        await _session_info_for_org(r, session_id, current_user.organization_id)
    finally:
        await r.aclose()
    pcap_path = f"{CAPTURES_DIR}/{session_id}.pcap"
    if not os.path.exists(pcap_path):
        raise HTTPException(status_code=404, detail="Capture file not found — session may still be running or has expired")
    return FileResponse(
        path=pcap_path,
        media_type="application/vnd.tcpdump.pcap",
        filename=f"capture-{session_id[:8]}.pcap",
    )


# ─── WebSocket streaming ─────────────────────────────────────────

@ws_router.websocket("/ws/capture/{session_id}")
async def capture_websocket(
    websocket: WebSocket,
    session_id: str,
    token: str = Query(...),
):
    """Stream captured packets to the browser in real time."""
    # Validate JWT, then require an active IT writer/admin whose organization
    # owns this capture session. Close before accept() on any failure.
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "access" or not payload.get("sub"):
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    try:
        session_id = _valid_session_id(session_id)
        async with AsyncSessionLocal() as db:
            user = (await db.execute(select(User).where(User.id == uuid.UUID(str(payload["sub"]))))).scalar_one_or_none()
        if not user or not user.is_active or user.role not in WRITE_ROLES:
            await websocket.close(code=1008)
            return
        redis_client = aioredis.from_url(settings.REDIS_URL, decode_responses=True)
        try:
            await _session_info_for_org(redis_client, session_id, user.organization_id)
        except HTTPException:
            await redis_client.aclose()
            await websocket.close(code=1008)
            return
    except Exception:
        await websocket.close(code=1008)
        return

    await websocket.accept()

    pubsub = redis_client.pubsub()
    await pubsub.subscribe(f"capture:{session_id}:stream")

    async def _forward():
        try:
            async for msg in pubsub.listen():
                if msg["type"] == "message":
                    try:
                        await websocket.send_text(msg["data"])
                    except Exception:
                        return
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    fwd_task = asyncio.create_task(_forward())

    try:
        while True:
            try:
                text = await asyncio.wait_for(websocket.receive_text(), timeout=25.0)
                if text == "ping":
                    await websocket.send_text('{"event":"pong"}')
            except asyncio.TimeoutError:
                await websocket.send_text('{"event":"ping"}')
            except WebSocketDisconnect:
                break
            except Exception:
                break
    finally:
        fwd_task.cancel()
        try:
            await pubsub.unsubscribe(f"capture:{session_id}:stream")
        except Exception:
            pass
        await redis_client.aclose()
