from fastapi import FastAPI
from sqlalchemy import text

from app.core.config import settings
from app.core.database import engine

from app.api.routes.auth import router as auth_router
from app.api.routes.users import router as users_router


app = FastAPI(title=settings.APP_NAME)

# Register routers
app.include_router(auth_router)
app.include_router(users_router)


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