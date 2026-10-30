"""
WebSocket connection manager.

Architecture:
  - Each connected browser holds a WebSocket to /ws/{org_id}
  - Celery workers publish scan events to Redis channel: ws:events:{org_id}
  - A background task in the API process subscribes to Redis and
    fans out messages to all connected sockets for that org

Event schema:
  {
    "event":    "scan_progress" | "scan_complete" | "scan_failed" | "finding_created",
    "scan_id":  "uuid",
    "payload":  { ... event-specific data ... }
  }
"""
import asyncio
import json
from typing import DefaultDict
from collections import defaultdict

import redis.asyncio as aioredis
from fastapi import WebSocket
import structlog

from app.core.config import settings

log = structlog.get_logger()


class WebSocketManager:
    """Manages active WebSocket connections grouped by organization ID."""

    def __init__(self):
        # org_id -> set of active WebSocket connections
        self._connections: DefaultDict[str, set[WebSocket]] = defaultdict(set)
        self._redis: aioredis.Redis | None = None
        self._pubsub_task: asyncio.Task | None = None

    async def startup(self):
        """Connect to Redis and start pub/sub listener. Called on app startup."""
        self._redis = aioredis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=True,
        )
        self._pubsub_task = asyncio.create_task(self._listen_redis())
        log.info("websocket_manager_started")

    async def shutdown(self):
        """Clean up on app shutdown."""
        if self._pubsub_task:
            self._pubsub_task.cancel()
        if self._redis:
            await self._redis.aclose()

    async def connect(self, websocket: WebSocket, org_id: str):
        await websocket.accept()
        self._connections[org_id].add(websocket)
        log.info("ws_client_connected", org_id=org_id, total=len(self._connections[org_id]))

    async def disconnect(self, websocket: WebSocket, org_id: str):
        self._connections[org_id].discard(websocket)
        if not self._connections[org_id]:
            del self._connections[org_id]
        log.info("ws_client_disconnected", org_id=org_id)

    async def broadcast_to_org(self, org_id: str, event: dict):
        """Send an event to all WebSocket clients in an org."""
        message = json.dumps(event)
        dead = set()
        for ws in list(self._connections.get(org_id, [])):
            try:
                await ws.send_text(message)
            except Exception:
                dead.add(ws)
        for ws in dead:
            self._connections[org_id].discard(ws)

    async def _listen_redis(self):
        """Background task: subscribe to all org channels and fan out events."""
        try:
            pubsub = self._redis.pubsub()
            # Subscribe to the pattern matching all org channels
            await pubsub.psubscribe("ws:events:*")
            async for message in pubsub.listen():
                if message["type"] != "pmessage":
                    continue
                try:
                    # Channel format: ws:events:{org_id}
                    channel = message["channel"]
                    org_id = channel.split(":", 2)[2]
                    event = json.loads(message["data"])
                    await self.broadcast_to_org(org_id, event)
                except Exception as e:
                    log.error("ws_relay_error", error=str(e))
        except asyncio.CancelledError:
            pass
        except Exception as e:
            log.error("ws_redis_listener_failed", error=str(e))


# ─── Global singleton ────────────────────────────────────────────
ws_manager = WebSocketManager()


# ─── Publisher (called from Celery tasks) ─────────────────────────

def publish_scan_event(org_id: str, event_type: str, scan_id: str, payload: dict):
    """
    Synchronous publisher — called from Celery workers.
    Uses a blocking Redis client since we're outside an async context.
    """
    import redis as sync_redis
    import json

    try:
        r = sync_redis.from_url(settings.REDIS_URL, decode_responses=True)
        message = json.dumps({
            "event": event_type,
            "scan_id": scan_id,
            "payload": payload,
        })
        r.publish(f"ws:events:{org_id}", message)
        r.close()
    except Exception as e:
        log.error("ws_publish_failed", event=event_type, error=str(e))
