from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)

from sqlalchemy.orm import Session

from app.api.dependencies.auth import (
    get_current_user,
    require_roles,
)

from app.core.database import get_db

from app.models.user import User

from app.schemas.threat import (
    ThreatIndicatorCreate,
    ThreatIndicatorResponse,
    ThreatIndicatorUpdate,
)

from app.services.threat_service import (
    create_threat_indicator,
    delete_threat_indicator,
    get_threat_by_id,
    get_threat_indicators,
    update_threat_indicator,
)


router = APIRouter(
    prefix="/threats",
    tags=["Threat Intelligence"],
)


@router.post(
    "/",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_threat(
    threat_data: ThreatIndicatorCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):

    return create_threat_indicator(
        db=db,
        threat_data=threat_data,
    )


@router.get(
    "/",
    response_model=list[ThreatIndicatorResponse],
    summary="List Threat Indicators",
)
def list_threats(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),

    search: str | None = Query(
        default=None,
        description="Search by IOC value",
    ),

    severity: str | None = Query(
        default=None,
        description="Filter by severity",
    ),

    indicator_type: str | None = Query(
        default=None,
        description="Filter by indicator type",
    ),

    source: str | None = Query(
        default=None,
        description="Filter by source",
    ),

    db: Session = Depends(get_db),

    current_user: User = Depends(
        get_current_user
    ),
):

    return get_threat_indicators(
        db=db,
        skip=skip,
        limit=limit,
        search=search,
        severity=severity,
        indicator_type=indicator_type,
        source=source,
    )


@router.get(
    "/{threat_id}",
    response_model=ThreatIndicatorResponse,
)
def get_threat(
    threat_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        get_current_user
    ),
):

    threat = get_threat_by_id(
        db=db,
        threat_id=threat_id,
    )

    if not threat:
        raise HTTPException(
            status_code=404,
            detail="Threat indicator not found",
        )

    return threat


@router.put(
    "/{threat_id}",
    response_model=ThreatIndicatorResponse,
)
def update_threat(
    threat_id: int,
    threat_data: ThreatIndicatorUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):

    threat = get_threat_by_id(
        db=db,
        threat_id=threat_id,
    )

    if not threat:
        raise HTTPException(
            status_code=404,
            detail="Threat indicator not found",
        )

    return update_threat_indicator(
        db=db,
        threat=threat,
        threat_data=threat_data,
    )


@router.delete(
    "/{threat_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_threat(
    threat_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin")
    ),
):

    threat = get_threat_by_id(
        db=db,
        threat_id=threat_id,
    )

    if not threat:
        raise HTTPException(
            status_code=404,
            detail="Threat indicator not found",
        )

    delete_threat_indicator(
        db=db,
        threat=threat,
    )

    return None