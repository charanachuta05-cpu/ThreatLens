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
from app.schemas.alert import (
    AlertCreate,
    AlertResponse,
    AlertSeverity,
    AlertStatus,
    AlertUpdate,
)
from app.services.alert_service import (
    create_alert,
    delete_alert,
    get_alert_by_id,
    get_alerts,
    update_alert,
)
from app.websockets.manager import manager


router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
)


# ============================================================
# CREATE ALERT
# ============================================================

@router.post(
    "/",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_new_alert(
    alert: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    """
    Create a new alert and broadcast the event
    to administrators and analysts.
    """

    created_alert = create_alert(
        db=db,
        alert_data=alert,
        created_by=current_user.id,
    )

    await manager.broadcast_to_roles(
        ["admin", "analyst"],
        {
            "event": "alert.created",
            "data": {
                "id": created_alert.id,
                "title": created_alert.title,
                "description": created_alert.description,
                "severity": created_alert.severity,
                "status": created_alert.status,
                "source": created_alert.source,
                "created_by": created_alert.created_by,
                "assigned_to": created_alert.assigned_to,
                "created_at": (
                    created_alert.created_at.isoformat()
                    if created_alert.created_at
                    else None
                ),
                "updated_at": (
                    created_alert.updated_at.isoformat()
                    if created_alert.updated_at
                    else None
                ),
            },
        },
    )

    return created_alert


# ============================================================
# LIST ALERTS
# ============================================================

@router.get(
    "/",
    response_model=list[AlertResponse],
    summary="Get alerts",
    description=(
        "Returns a paginated list of alerts with optional "
        "severity, status, source, and text search filters."
    ),
)
def list_alerts(
    skip: int = Query(
        default=0,
        ge=0,
        description="Number of records to skip.",
    ),
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of alerts to return.",
    ),
    severity: AlertSeverity | None = Query(
        default=None,
        description="Filter by alert severity.",
    ),
    status_filter: AlertStatus | None = Query(
        default=None,
        alias="status",
        description="Filter by alert status.",
    ),
    source: str | None = Query(
        default=None,
        min_length=1,
        max_length=100,
        description="Filter by alert source.",
    ),
    search: str | None = Query(
        default=None,
        min_length=1,
        max_length=255,
        description=(
            "Search alert title and description."
        ),
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve alerts with pagination and filtering.

    Supported filters:

        ?severity=CRITICAL
        ?status=OPEN
        ?source=Pipeline-Test
        ?search=PowerShell

    Multiple filters can be combined.
    """

    return get_alerts(
        db=db,
        skip=skip,
        limit=limit,
        severity=severity,
        status=status_filter,
        source=source,
        search=search,
    )


# ============================================================
# GET ALERT BY ID
# ============================================================

@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get alert by ID",
    description="Retrieve a specific alert using its ID.",
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve a single alert.
    """

    alert = get_alert_by_id(
        db=db,
        alert_id=alert_id,
    )

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    return alert


# ============================================================
# UPDATE ALERT
# ============================================================

@router.put(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Update Existing Alert",
    description=(
        "Partially update an alert and broadcast the "
        "updated event to administrators and analysts."
    ),
)
async def update_existing_alert(
    alert_id: int,
    alert_data: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    """
    Update an alert and broadcast the updated event.
    """

    alert = get_alert_by_id(
        db=db,
        alert_id=alert_id,
    )

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    updated_alert = update_alert(
        db=db,
        alert=alert,
        alert_data=alert_data,
    )

    await manager.broadcast_to_roles(
        ["admin", "analyst"],
        {
            "event": "alert.updated",
            "data": {
                "id": updated_alert.id,
                "title": updated_alert.title,
                "description": updated_alert.description,
                "severity": updated_alert.severity,
                "status": updated_alert.status,
                "source": updated_alert.source,
                "created_by": updated_alert.created_by,
                "assigned_to": updated_alert.assigned_to,
                "created_at": (
                    updated_alert.created_at.isoformat()
                    if updated_alert.created_at
                    else None
                ),
                "updated_at": (
                    updated_alert.updated_at.isoformat()
                    if updated_alert.updated_at
                    else None
                ),
            },
        },
    )

    return updated_alert


# ============================================================
# DELETE ALERT
# ============================================================

@router.delete(
    "/{alert_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete Alert",
    description=(
        "Delete an alert and broadcast the deletion "
        "event to administrators."
    ),
)
async def remove_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin")
    ),
):
    """
    Delete an alert and broadcast the deletion event.
    """

    alert = get_alert_by_id(
        db=db,
        alert_id=alert_id,
    )

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    deleted_alert_id = alert.id

    delete_alert(
        db=db,
        alert=alert,
    )

    await manager.broadcast_to_role(
        "admin",
        {
            "event": "alert.deleted",
            "data": {
                "id": deleted_alert_id,
            },
        },
    )

    return None