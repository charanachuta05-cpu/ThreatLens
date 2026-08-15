from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.dependencies.auth import require_roles
from app.core.database import get_db
from app.models.user import User
from app.schemas.audit import AuditEventResponse
from app.services.audit_service import get_audit_events


router = APIRouter(
    prefix="/admin",
    tags=["Admin"],
)


@router.get("/dashboard")
def admin_dashboard(
    current_user: User = Depends(require_roles("admin")),
):
    return {
        "message": "Welcome Admin",
        "user": current_user.username,
    }


@router.get(
    "/audit-events",
    response_model=list[AuditEventResponse],
    summary="Get security audit events",
    description=(
        "Returns persistent security audit events. "
        "This endpoint is restricted to administrators."
    ),
)
def list_audit_events(
    skip: int = Query(
        default=0,
        ge=0,
        description="Number of records to skip.",
    ),
    limit: int = Query(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of audit events to return.",
    ),
    action: str | None = Query(
        default=None,
        min_length=1,
        max_length=100,
        description="Filter by audit action.",
    ),
    actor: str | None = Query(
        default=None,
        min_length=1,
        max_length=100,
        description="Filter by audit actor.",
    ),
    target: str | None = Query(
        default=None,
        min_length=1,
        max_length=255,
        description="Filter by audit target.",
    ),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin")
    ),
):
    """
    Retrieve security audit events.

    Administrators can filter events by action, actor,
    and target. Results are returned newest first.
    """

    return get_audit_events(
        db=db,
        skip=skip,
        limit=limit,
        action=action,
        actor=actor,
        target=target,
    )
