from fastapi import (
    APIRouter,
    WebSocket,
    WebSocketDisconnect,
    status,
)

from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.logging.logger import logger
from app.websockets.auth import verify_websocket_token
from app.websockets.manager import manager


router = APIRouter()


@router.websocket("/ws/alerts")
async def websocket_endpoint(websocket: WebSocket):

    logger.info("WebSocket connection attempt")

    db: Session = SessionLocal()

    try:
        token = websocket.query_params.get("token")

        if not token:
            logger.warning(
                "WebSocket connection rejected: no token provided"
            )

            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION
            )
            return

        user = verify_websocket_token(token, db)

        if user is None:
            logger.warning(
                "WebSocket connection rejected: invalid token"
            )

            await websocket.close(
                code=status.WS_1008_POLICY_VIOLATION
            )
            return

        logger.info(
            "WebSocket authentication successful: "
            "user=%s role=%s",
            user.username,
            user.role,
        )

        await manager.connect(websocket, user)

        try:
            while True:
                await websocket.receive_text()

        except WebSocketDisconnect:
            logger.info("WebSocket client disconnected")
            manager.disconnect(websocket)

    finally:
        db.close()
