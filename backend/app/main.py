import asyncio
from contextlib import asynccontextmanager

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
from app.logging.logger import logger

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


# -------------------------------------------------
# Application Lifecycle
# -------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage application startup and shutdown lifecycle.
    """

    # Store the main FastAPI event loop.
    # Background workers use this when WebSocket
    # notifications are required.
    events.websocket_loop = asyncio.get_running_loop()

    logger.info("Main event loop stored")

    # Do not run background workers during tests.
    #
    # This prevents the simulated threat-intelligence
    # feed from modifying the database while pytest
    # is executing.
    if settings.APP_ENV.lower() == "test":
        logger.info("Test environment detected")
        logger.info("Background scheduler disabled")
    else:
        start_scheduler()
        logger.info("Background scheduler started")

    try:
        yield

    finally:
        # Stop background workers during normal
        # application shutdown.
        if settings.APP_ENV.lower() != "test":
            stop_scheduler()
            logger.info("Background scheduler stopped")
        else:
            logger.info("Test environment: scheduler shutdown skipped")

        # Clear the stored event loop reference.
        events.websocket_loop = None

        logger.info("Main event loop cleared")


app = FastAPI(
    title=settings.APP_NAME,
    lifespan=lifespan,
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
logger.info("WebSocket router registered")

app.include_router(websocket_status_router)

app.include_router(threat_intel.router)
app.include_router(investigations.router)
app.include_router(threat_hunting.router)
app.include_router(dashboard.router)


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

    except Exception:
        logger.exception("Health check database connection failed")

        return {
            "status": "unhealthy",
            "database": "disconnected",
        }
