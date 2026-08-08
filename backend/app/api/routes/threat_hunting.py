from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import SessionLocal

from app.threat_hunting.service import (
    hunt_high_risk,
    hunt_recent,
    hunt_by_source,
)

router = APIRouter(
    prefix="/hunt",
    tags=["Threat Hunting"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/high-risk")
def high_risk(
    db: Session = Depends(get_db),
):
    return hunt_high_risk(db)


@router.get("/recent")
def recent(
    limit: int = 20,
    db: Session = Depends(get_db),
):
    return hunt_recent(
        db,
        limit,
    )


@router.get("/source/{source}")
def by_source(
    source: str,
    db: Session = Depends(get_db),
):
    return hunt_by_source(
        db,
        source,
    )