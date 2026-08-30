from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
)
from sqlalchemy.orm import Session

from app.api.dependencies.auth import (
    require_roles,
)
from app.core.database import get_db
from app.correlation.schemas import (
    CorrelationResponse,
)
from app.correlation.service import (
    correlate_indicator,
)
from app.models.user import User


router = APIRouter(
    prefix="/correlation",
    tags=["Correlation"],
)


@router.get(
    "/{indicator_id}",
    response_model=CorrelationResponse,
    summary="Correlate threat indicator",
    description=(
        "Analyzes a persisted threat indicator "
        "against other ThreatLens indicators and "
        "returns deterministic relationships, "
        "correlation scores, reasons, and related "
        "security alerts."
    ),
)
def get_indicator_correlation(
    indicator_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles(
            "admin",
            "analyst",
        ),
    ),
):
    del current_user

    try:
        return correlate_indicator(
            db=db,
            indicator_id=indicator_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=404,
            detail="Indicator not found.",
        ) from exc