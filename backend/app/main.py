from fastapi import FastAPI
from sqlalchemy import text

from app.core.config import settings
from app.core.database import engine

app = FastAPI(title=settings.APP_NAME)


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