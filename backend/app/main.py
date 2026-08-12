import asyncio

from fastapi import FastAPI, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.core.database import engine
from app.core.exceptions import (
    database_exception_handler,
    global_exception_handler,
    http_exception_handler,
    validation_exception_handler,
)

from app.api.routes import (
    admin,
    alerts,
    auth,
    dashboard,
    investigations,
    threat_hunting,
    threat_intel,
    threats,
    users,
)

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
# CORS Configuration
# -------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# -------------------------------------------------
# Exception Handlers
# -------------------------------------------------

app.add_exception_handler(
    HTTPException,
    http_exception_handler,
)

app.add_exception_handler(
    RequestValidationError,
    validation_exception_handler,
)

app.add_exception_handler(
    SQLAlchemyError,
    database_exception_handler,
)

app.add_exception_handler(
    Exception,
    global_exception_handler,
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
app.include_router(investigations.router)
app.include_router(threat_hunting.router)
app.include_router(dashboard.router)


# -------------------------------------------------
# Application Lifecycle
# -------------------------------------------------

@app.on_event("startup")
async def startup_event():

    # Store FastAPI main event loop.
    # APScheduler workers use this when
    # WebSocket notifications are required.
    events.websocket_loop = asyncio.get_running_loop()

    print("✅ Main event loop stored")

    # Do not run background workers during tests.
    #
    # This prevents the simulated threat-intelligence
    # feed from modifying the database while pytest
    # is executing.
    if settings.APP_ENV.lower() == "test":
        print("🧪 Test environment detected")
        print("⏸️ Background scheduler disabled")
        return

    start_scheduler()

    print("✅ Background scheduler started")


@app.on_event("shutdown")
async def shutdown_event():

    if settings.APP_ENV.lower() != "test":
        stop_scheduler()
        print("🛑 Background scheduler stopped")
    else:
        print("🧪 Test environment: scheduler shutdown skipped")

    events.websocket_loop = None

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