from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.dependencies.auth import require_roles
from app.core.database import get_db
from app.models.user import User
from app.threat_hunting.schemas import HuntResult
from app.threat_hunting.service import (
    hunt_by_source,
    hunt_high_risk,
    hunt_recent,
)

router = APIRouter(
    prefix="/hunt",
    tags=["Threat Hunting"],
)


@router.get(
    "/high-risk",
    response_model=list[HuntResult],
)
def high_risk(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    return hunt_high_risk(db)


@router.get(
    "/recent",
    response_model=list[HuntResult],
)
def recent(
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    return hunt_recent(
        db,
        limit,
    )


@router.get(
    "/source/{source}",
    response_model=list[HuntResult],
)
def by_source(
    source: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    return hunt_by_source(
        db,
        source,
    )
