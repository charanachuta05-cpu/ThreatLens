from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.access_request import AccessRequest
from app.models.audit import AuditEvent
from app.models.user import User


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _response(
    request: AccessRequest,
    user: User,
) -> dict:
    return {
        "id": request.id,
        "user_id": user.id,
        "username": user.username,
        "email": user.email,
        "requested_role": request.requested_role,
        "status": request.status,
        "reviewed_by": request.reviewed_by,
        "created_at": request.created_at,
        "reviewed_at": request.reviewed_at,
    }


def create_analyst_request(
    db: Session,
    current_user: User,
) -> dict:
    if not current_user.is_active:
        raise HTTPException(
            status_code=403,
            detail="Inactive accounts cannot request access.",
        )

    if current_user.role != "viewer":
        raise HTTPException(
            status_code=400,
            detail="Only viewers can request analyst access.",
        )

    existing = (
        db.query(AccessRequest)
        .filter(
            AccessRequest.user_id == current_user.id,
            AccessRequest.status == "pending",
        )
        .first()
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail="An analyst access request is already pending.",
        )

    request = AccessRequest(
        user_id=current_user.id,
        requested_role="analyst",
        status="pending",
    )

    audit = AuditEvent(
        action="REQUEST_ANALYST_ACCESS",
        actor=current_user.email,
        target=f"user:{current_user.id}",
    )

    db.add(request)
    db.add(audit)
    db.commit()
    db.refresh(request)

    return _response(request, current_user)


def get_my_request(
    db: Session,
    current_user: User,
) -> dict | None:
    request = (
        db.query(AccessRequest)
        .filter(
            AccessRequest.user_id == current_user.id,
        )
        .order_by(
            AccessRequest.created_at.desc(),
            AccessRequest.id.desc(),
        )
        .first()
    )

    if request is None:
        return None

    return _response(request, current_user)


def get_pending_requests(
    db: Session,
) -> list[dict]:
    rows = (
        db.query(AccessRequest, User)
        .join(
            User,
            User.id == AccessRequest.user_id,
        )
        .filter(
            AccessRequest.status == "pending",
        )
        .order_by(
            AccessRequest.created_at.asc(),
            AccessRequest.id.asc(),
        )
        .all()
    )

    return [
        _response(request, user)
        for request, user in rows
    ]


def approve_request(
    db: Session,
    request_id: int,
    admin: User,
) -> dict:
    request = (
        db.query(AccessRequest)
        .filter(AccessRequest.id == request_id)
        .first()
    )

    if request is None:
        raise HTTPException(
            status_code=404,
            detail="Access request not found.",
        )

    if request.status != "pending":
        raise HTTPException(
            status_code=409,
            detail="Access request has already been reviewed.",
        )

    if request.requested_role != "analyst":
        raise HTTPException(
            status_code=400,
            detail="Unsupported requested role.",
        )

    user = (
        db.query(User)
        .filter(User.id == request.user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="Requested user not found.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=400,
            detail="Inactive users cannot be promoted.",
        )

    if user.role != "viewer":
        raise HTTPException(
            status_code=409,
            detail="User is no longer eligible for analyst promotion.",
        )

    reviewed_at = utc_now()

    user.role = "analyst"
    request.status = "approved"
    request.reviewed_by = admin.id
    request.reviewed_at = reviewed_at

    audit = AuditEvent(
        action="APPROVE_ANALYST_ACCESS",
        actor=admin.email,
        target=f"user:{user.id}",
    )

    db.add(audit)
    db.commit()
    db.refresh(request)
    db.refresh(user)

    return _response(request, user)


def reject_request(
    db: Session,
    request_id: int,
    admin: User,
) -> dict:
    request = (
        db.query(AccessRequest)
        .filter(AccessRequest.id == request_id)
        .first()
    )

    if request is None:
        raise HTTPException(
            status_code=404,
            detail="Access request not found.",
        )

    if request.status != "pending":
        raise HTTPException(
            status_code=409,
            detail="Access request has already been reviewed.",
        )

    user = (
        db.query(User)
        .filter(User.id == request.user_id)
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=404,
            detail="Requested user not found.",
        )

    request.status = "rejected"
    request.reviewed_by = admin.id
    request.reviewed_at = utc_now()

    audit = AuditEvent(
        action="REJECT_ANALYST_ACCESS",
        actor=admin.email,
        target=f"user:{user.id}",
    )

    db.add(audit)
    db.commit()
    db.refresh(request)

    return _response(request, user)
