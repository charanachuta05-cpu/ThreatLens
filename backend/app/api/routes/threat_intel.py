from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.dependencies.auth import (
    get_current_user,
    require_roles,
)
from app.core.database import get_db
from app.models.user import User

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


@router.post(
    "/",
    response_model=IndicatorResponse,
    dependencies=[
        Depends(
            require_roles(
                "admin",
                "analyst",
            )
        )
    ],
)
def create(
    indicator: IndicatorCreate,
    db: Session = Depends(get_db),
):
    """
    Create a new threat intelligence indicator.

    Access:
        admin
        analyst
    """

    return create_indicator(
        db=db,
        indicator=indicator,
    )


@router.get(
    "/",
    response_model=list[IndicatorResponse],
)
def list_indicators(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
    skip: Annotated[
        int,
        Query(ge=0),
    ] = 0,
    limit: Annotated[
        int,
        Query(ge=1, le=100),
    ] = 20,
    search: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    min_score: Annotated[
        int | None,
        Query(ge=0, le=100),
    ] = None,
    sort_by: str = "created_at",
    order: str = "desc",
):
    """
    Retrieve threat intelligence indicators.

    Any authenticated user can read indicators.
    """

    return get_indicators(
        db=db,
        skip=skip,
        limit=limit,
        search=search,
        severity=severity,
        source=source,
        min_score=min_score,
        sort_by=sort_by,
        order=order,
    )