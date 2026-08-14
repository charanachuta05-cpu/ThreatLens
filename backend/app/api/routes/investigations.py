from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.dependencies.auth import require_roles
from app.core.database import SessionLocal
from app.investigation.schemas import InvestigationResponse
from app.investigation.service import investigate_indicator
from app.models.user import User


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
)
def investigate(
    indicator_id: int,
    current_user: User = Depends(
        require_roles("admin", "analyst"),
    ),
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
            detail=str(exc),
        ) from exc