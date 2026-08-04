from app.websockets.manager import manager
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
    AlertUpdate,
)
from app.services.alert_service import (
    create_alert,
    delete_alert,
    get_alert_by_id,
    get_alerts,
    update_alert,
)

router = APIRouter(
    prefix="/alerts",
    tags=["Alerts"],
)


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
    created_alert = create_alert(
        db=db,
        alert_data=alert,
        created_by=current_user.id,
    )

    await manager.broadcast(
        {
            "event": "alert.created",
            "data": {
                "id": created_alert.id,
                "title": created_alert.title,
                "description": created_alert.description,
                "severity": created_alert.severity,
                "status": created_alert.status,
                "source": created_alert.source,
            },
        }
    )

    return created_alert


@router.get(
    "/",
    response_model=list[AlertResponse],
    summary="Get all alerts",
    description="Returns a paginated list of alerts.",
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
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve all alerts.
    """

    return get_alerts(
        db=db,
        skip=skip,
        limit=limit,
    )


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


@router.put("/{alert_id}", response_model=AlertResponse)
async def update_existing_alert(
    alert_id: int,
    alert_data: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin", "analyst")),
):
    alert = get_alert_by_id(db=db, alert_id=alert_id)

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

    await manager.broadcast(
        {
            "event": "alert.updated",
            "data": {
                "id": updated_alert.id,
                "title": updated_alert.title,
                "description": updated_alert.description,
                "severity": updated_alert.severity,
                "status": updated_alert.status,
                "source": updated_alert.source,
                "assigned_to": updated_alert.assigned_to,
            },
        }
    )

    return updated_alert

@router.delete(
    "/{alert_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def remove_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_roles("admin")),
):
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

    await manager.broadcast(
        {
            "event": "alert.deleted",
            "data": {
                "id": deleted_alert_id,
            },
        }
    )

    return None