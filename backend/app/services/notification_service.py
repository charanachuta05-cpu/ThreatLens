import asyncio
import logging

from app.websockets.manager import manager
from app.core.events import websocket_loop


logger = logging.getLogger(__name__)


async def broadcast_alert_created(alert):
    """
    Broadcast alert creation event.
    """

    payload = {
        "event": "alert.created",
        "data": {
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity,
            "status": alert.status,
        },
    }

    await manager.broadcast(payload)


def broadcast_alert_created_background(alert):
    """
    Safe WebSocket broadcast trigger.

    Works from:
    - FastAPI async routes
    - APScheduler background threads
    """

    try:
        loop = asyncio.get_running_loop()

        loop.create_task(
            broadcast_alert_created(alert)
        )

    except RuntimeError:

        logger.warning(
            "No running event loop. "
            "Scheduling WebSocket broadcast on main loop."
        )

        from app.core.events import websocket_loop

        if websocket_loop:

            asyncio.run_coroutine_threadsafe(
                broadcast_alert_created(alert),
                websocket_loop,
            )

def broadcast_alert_created_background(alert):

    try:
        loop = asyncio.get_running_loop()

        loop.create_task(
            broadcast_alert_created(alert)
        )

    except RuntimeError:

        from app.core.events import websocket_loop

        if websocket_loop:

            asyncio.run_coroutine_threadsafe(
                broadcast_alert_created(alert),
                websocket_loop,
            )

        else:
            logger.error(
                "WebSocket event loop not initialized"
            )