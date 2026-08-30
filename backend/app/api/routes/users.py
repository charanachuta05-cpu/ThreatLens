from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.auth import (
    get_current_user,
    require_roles,
)
from app.core.database import get_db
from app.models.user import User
from app.schemas.user import UserResponse


router = APIRouter(
    prefix="/users",
    tags=["Users"],
)


@router.get("/me")
def get_me(
    current_user: User = Depends(get_current_user),
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
    }


@router.get(
    "/assignable",
    response_model=list[UserResponse],
    summary="Get active alert assignees",
    description=(
        "Returns active administrators and analysts "
        "who can be assigned to security alerts."
    ),
)
def get_assignable_users(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    """
    Return active users eligible for alert assignment.

    Only administrators and analysts are exposed.
    Viewers and inactive accounts are intentionally excluded.
    """

    return (
        db.query(User)
        .filter(
            User.is_active.is_(True),
            User.role.in_(("admin", "analyst")),
        )
        .order_by(
            User.role.asc(),
            User.username.asc(),
            User.id.asc(),
        )
        .all()
    )


# -------------------------
# Analyst Access Requests
# -------------------------

from app.schemas.user import (
    AccessRequestResponse,
    AccessRequestStatusResponse,
)
from app.services.access_request_service import (
    approve_request,
    create_analyst_request,
    get_my_request,
    get_pending_requests,
    reject_request,
)


@router.post(
    "/access-requests",
    response_model=AccessRequestResponse,
    status_code=201,
)
def request_analyst_access(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return create_analyst_request(
        db,
        current_user,
    )


@router.get(
    "/access-requests/me",
    response_model=AccessRequestStatusResponse | None,
)
def read_my_access_request(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    request = get_my_request(
        db,
        current_user,
    )

    if request is None:
        return None

    return {
        "id": request["id"],
        "requested_role": request["requested_role"],
        "status": request["status"],
        "created_at": request["created_at"],
        "reviewed_at": request["reviewed_at"],
    }


@router.get(
    "/access-requests/pending",
    response_model=list[AccessRequestResponse],
)
def read_pending_access_requests(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin")
    ),
):
    return get_pending_requests(db)


@router.post(
    "/access-requests/{request_id}/approve",
    response_model=AccessRequestResponse,
)
def approve_analyst_access(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin")
    ),
):
    return approve_request(
        db,
        request_id,
        current_user,
    )


@router.post(
    "/access-requests/{request_id}/reject",
    response_model=AccessRequestResponse,
)
def reject_analyst_access(
    request_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin")
    ),
):
    return reject_request(
        db,
        request_id,
        current_user,
    )
