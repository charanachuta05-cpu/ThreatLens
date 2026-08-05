from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.threat_intel.schemas import (
    IndicatorCreate,
    IndicatorResponse,
)
from app.threat_intel.service import (
    create_indicator,
    get_indicators,
)


router = APIRouter(
    prefix="/indicators",
    tags=["Threat Intelligence"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/", response_model=IndicatorResponse)
def create(
    indicator: IndicatorCreate,
    db: Session = Depends(get_db),
):
    return create_indicator(db, indicator)


@router.get("/", response_model=list[IndicatorResponse])
def list_all(
    db: Session = Depends(get_db),
):
    return get_indicators(db)