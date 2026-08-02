from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.schemas.alert import AlertCreate, AlertUpdate


def create_alert(
    db: Session,
    alert_data: AlertCreate,
    created_by: int,
) -> Alert:
    """
    Create a new alert.
    """

    alert = Alert(
        title=alert_data.title,
        description=alert_data.description,
        severity=alert_data.severity,
        source=alert_data.source,
        assigned_to=alert_data.assigned_to,
        created_by=created_by,
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

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
):
    """
    Retrieve alerts with pagination.
    """

    return (
        db.query(Alert)
        .offset(skip)
        .limit(limit)
        .all()
    )


def update_alert(
    db: Session,
    alert: Alert,
    alert_data: AlertUpdate,
) -> Alert:
    """
    Update an existing alert.
    """

    update_data = alert_data.model_dump(exclude_unset=True)

    for key, value in update_data.items():
        setattr(alert, key, value)

    db.commit()
    db.refresh(alert)

    return alert


def delete_alert(
    db: Session,
    alert: Alert,
) -> None:
    """
    Delete an alert.
    """

    db.delete(alert)
    db.commit()