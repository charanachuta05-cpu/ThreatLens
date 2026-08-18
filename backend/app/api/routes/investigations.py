from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies.auth import require_roles
from app.core.database import SessionLocal
from app.investigation.schemas import InvestigationResponse
from app.investigation.service import investigate_indicator


router = APIRouter(
    prefix="/investigations",
    tags=["Investigations"],
)


def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


@router.get(
    "/{indicator_id}",
    response_model=InvestigationResponse,
    dependencies=[
        Depends(
            require_roles("admin", "analyst"),
        )
    ],
)
def investigate(
    indicator_id: int,
    db: Session = Depends(get_db),
):
    try:
        return investigate_indicator(
            db,
            indicator_id,
        )

    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail="Indicator not found.",
        ) from exc
