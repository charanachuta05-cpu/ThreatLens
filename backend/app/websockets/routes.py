from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
    status,
)

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.websockets.manager import manager
from app.websockets.auth import verify_websocket_token

router = APIRouter()


@router.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):

    print("=== WebSocket connection attempt ===")

    db: Session = SessionLocal()

    try:
        token = websocket.query_params.get("token")
        print("Token received:", token)

        if not token:
            print("❌ No token provided")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        user = verify_websocket_token(token, db)
        print("Authenticated user:", user)

        if user is None:
            print("❌ Invalid token")
            await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
            return

        print("✅ Token valid")

        await manager.connect(websocket, user)

        try:
            while True:
                await websocket.receive_text()

        except WebSocketDisconnect:
            print("Client disconnected")
            manager.disconnect(websocket)

    finally:
        db.close()