from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
    status,
)

from app.websockets.manager import manager
from app.websockets.auth import verify_websocket_token

router = APIRouter()


@router.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):

    print("=== WebSocket connection attempt ===")

    token = websocket.query_params.get("token")
    print("Token received:", token)

    if not token:
        print("❌ No token provided")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    payload = verify_websocket_token(token)
    print("Decoded payload:", payload)

    if payload is None:
        print("❌ Invalid token")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    print("✅ Token valid")

    await manager.connect(websocket)

    try:
        while True:
            await websocket.receive_text()

    except WebSocketDisconnect:
        print("Client disconnected")
        manager.disconnect(websocket)