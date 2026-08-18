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
