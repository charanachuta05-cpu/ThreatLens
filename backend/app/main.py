import asyncio

from fastapi import FastAPI
from sqlalchemy import text

from app.core.config import settings
from app.core.database import engine

from app.api.routes import threats
from app.api.routes import threat_intel
from app.api.routes import auth, users, alerts, admin

from app.websockets.routes import router as websocket_router
from app.websockets.status import router as websocket_status_router

from app.workers.scheduler import (
    start_scheduler,
    stop_scheduler,
)

import app.core.events as events


app = FastAPI(
    title=settings.APP_NAME,
)


# -------------------------------------------------
# Router Registration
# -------------------------------------------------

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(alerts.router)
app.include_router(threats.router)

app.include_router(websocket_router)
print("✅ WebSocket router registered")

app.include_router(websocket_status_router)

app.include_router(threat_intel.router)


# -------------------------------------------------
# Application Lifecycle
# -------------------------------------------------

@app.on_event("startup")
async def startup_event():

    # Store FastAPI main event loop.
    # APScheduler workers will use this loop
    # for WebSocket broadcasts.
    events.websocket_loop = asyncio.get_running_loop()

    print("✅ Main event loop stored")

    start_scheduler()

    print("✅ Background scheduler started")


@app.on_event("shutdown")
async def shutdown_event():

    stop_scheduler()

    events.websocket_loop = None

    print("🛑 Background scheduler stopped")
    print("🛑 Main event loop cleared")


# -------------------------------------------------
# Root Endpoint
# -------------------------------------------------

@app.get("/")
def root():

    return {
        "application": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "debug": settings.DEBUG,
    }


# -------------------------------------------------
# Health Check
# -------------------------------------------------

@app.get("/health")
def health():

    try:

        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))

        return {
            "status": "healthy",
            "database": "connected",
        }

    except Exception as e:

        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e),
        }