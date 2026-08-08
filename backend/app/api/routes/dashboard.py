from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import SessionLocal

from app.dashboard.service import (
    get_dashboard_summary,
)

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/summary")
def summary(
    db: Session = Depends(get_db),
):
    return get_dashboard_summary(db)