"""
WebSocket endpoint.
ws://{host}/ws/{org_id}?token={jwt_access_token}

Clients authenticate by passing their JWT as a query param
(WebSocket API doesn't support custom headers in browsers).
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, status
import jwt
from jwt import PyJWTError as JWTError

from app.core.config import settings
from app.core.websocket import ws_manager

router = APIRouter(tags=["websocket"])


async def _authenticate_ws(token: str, org_id: str) -> bool:
    """Validate JWT and confirm user belongs to the org."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "access":
            return False
        user_id = payload.get("sub")
        token_org = payload.get("org")
        # Confirm token org matches requested org
        if str(token_org) != str(org_id):
            return False
        return True
    except JWTError:
        return False


@router.websocket("/ws/{org_id}")
async def websocket_endpoint(
    websocket: WebSocket,
    org_id: str,
    token: str = Query(...),
):
    # Authenticate before accepting
    if not await _authenticate_ws(token, org_id):
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    await ws_manager.connect(websocket, org_id)
    try:
        # Send a welcome ping so the client knows it's connected
        await websocket.send_json({"event": "connected", "org_id": org_id})

        # Keep connection alive — client sends pings, we pong
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")

    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(websocket, org_id)
