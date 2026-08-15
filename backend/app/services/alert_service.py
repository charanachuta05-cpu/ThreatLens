from fastapi import HTTPException, status
from sqlalchemy.exc import SQLAlchemyError

from app.models.user import User
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.schemas.alert import (
    AlertCreate,
    AlertSeverity,
    AlertStatus,
    AlertUpdate,
)


def create_alert(
    db: Session,
    alert_data: AlertCreate,
    created_by: int | None,
    *,
    commit: bool = True,
) -> Alert:
    """
    Create a new alert.

    By default, the function commits the transaction for
    normal API usage.

    When commit=False is supplied, the alert is flushed
    but the transaction remains open. This allows callers
    performing multi-step operations to commit or roll back
    the entire operation atomically.

    WebSocket broadcasting is handled by the API route.
    """

    alert = Alert(
        title=alert_data.title,
        description=alert_data.description,
        severity=alert_data.severity,
        status=AlertStatus.OPEN,
        source=alert_data.source,
        created_by=created_by,
    )

    db.add(alert)

    if commit:
        db.commit()
        db.refresh(alert)

    else:
        db.flush()

    return alert


def get_alert_by_id(
    db: Session,
    alert_id: int,
) -> Alert | None:
    """
    Retrieve an alert by ID.
    """

    return (
        db.query(Alert)
        .filter(Alert.id == alert_id)
        .first()
    )


def get_alerts(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    severity: AlertSeverity | None = None,
    status: AlertStatus | None = None,
    source: str | None = None,
    search: str | None = None,
) -> list[Alert]:
    """
    Retrieve alerts with pagination and optional filtering.

    Supported filters:
        - severity
        - status
        - source
        - search

    Results are ordered newest first.
    """

    query = db.query(Alert)

    # --------------------------------------------------------
    # Severity filter
    # --------------------------------------------------------

    if severity is not None:
        query = query.filter(
            Alert.severity == severity
        )

    # --------------------------------------------------------
    # Status filter
    # --------------------------------------------------------

    if status is not None:
        query = query.filter(
            Alert.status == status
        )

    # --------------------------------------------------------
    # Source filter
    # --------------------------------------------------------

    if source:
        query = query.filter(
            Alert.source.ilike(f"%{source}%")
        )

    # --------------------------------------------------------
    # Search filter
    #
    # Searches both title and description.
    # --------------------------------------------------------

    if search:
        search_pattern = f"%{search}%"

        query = query.filter(
            or_(
                Alert.title.ilike(search_pattern),
                Alert.description.ilike(search_pattern),
            )
        )

    # --------------------------------------------------------
    # Deterministic ordering
    # --------------------------------------------------------

    query = query.order_by(
        Alert.created_at.desc(),
        Alert.id.desc(),
    )

    # --------------------------------------------------------
    # Pagination
    # --------------------------------------------------------

    return (
        query
        .offset(skip)
        .limit(limit)
        .all()
    )


def update_alert(
    db: Session,
    alert: Alert,
    alert_data: AlertUpdate,
    *,
    commit: bool = True,
) -> Alert:
    """
    Safely update an existing alert.

    Only explicitly supplied fields are modified.

    assigned_to is validated before the alert is changed.
    The assigned user must exist and be active.

    When commit=False is supplied, the alert is flushed but
    the transaction remains open so callers can perform
    additional atomic operations such as audit logging.
    """

    update_data = alert_data.model_dump(
        exclude_unset=True,
    )

    # --------------------------------------------------------
    # Validate assigned user
    # --------------------------------------------------------

    if "assigned_to" in update_data:
        assigned_to = update_data["assigned_to"]

        # None explicitly clears the assignment.
        if assigned_to is not None:
            assigned_user = (
                db.query(User)
                .filter(
                    User.id == assigned_to,
                    User.is_active.is_(True),
                )
                .first()
            )

            if assigned_user is None:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Assigned user not found or inactive",
                )

    # --------------------------------------------------------
    # Apply validated changes
    # --------------------------------------------------------

    for key, value in update_data.items():
        setattr(alert, key, value)

    # --------------------------------------------------------
    # Persist changes
    # --------------------------------------------------------

    try:
        if commit:
            db.commit()
            db.refresh(alert)
        else:
            db.flush()

    except SQLAlchemyError:
        db.rollback()
        raise

    return alert


def delete_alert(
    db: Session,
    alert: Alert,
    *,
    commit: bool = True,
) -> None:
    """
    Delete an alert.

    When commit=False is supplied, the deletion is flushed but
    the transaction remains open so callers can perform
    additional atomic operations such as audit logging.
    """

    db.delete(alert)

    try:
        if commit:
            db.commit()
        else:
            db.flush()

    except SQLAlchemyError:
        db.rollback()
        raise


def get_alert_by_title(
    db: Session,
    title: str,
) -> Alert | None:
    """
    Check whether an alert with the given title exists.
    """

    return (
        db.query(Alert)
        .filter(Alert.title == title)
        .first()
    )