from fastapi import FastAPI
from sqlalchemy import text

from app.core.config import settings
from app.core.database import engine

from app.api.routes import threats

from app.api.routes import auth, users, alerts, admin


app = FastAPI(
    title=settings.APP_NAME,
)


# Register routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(admin.router)
app.include_router(alerts.router)
app.include_router(threats.router)


@app.get("/")
def root():
    return {
        "application": settings.APP_NAME,
        "environment": settings.APP_ENV,
        "debug": settings.DEBUG,
    }


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