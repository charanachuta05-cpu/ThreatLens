from datetime import datetime, timezone

from fastapi import HTTPException, status
from sqlalchemy import or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.incident import (
    Incident,
    IncidentNote,
    IncidentResolutionType,
    IncidentStatus,
)
from app.models.user import User
from app.schemas.incident import (
    IncidentCreate,
    IncidentNoteCreate,
    IncidentResolve,
    IncidentUpdate,
)
from app.threat_intel.models import Indicator


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _validate_assignee(
    db: Session,
    user_id: int | None,
) -> None:
    if user_id is None:
        return

    user = (
        db.query(User)
        .filter(
            User.id == user_id,
            User.is_active.is_(True),
            User.role.in_(("admin", "analyst")),
        )
        .first()
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Assignable user not found or inactive",
        )


def _get_alerts_by_ids(
    db: Session,
    alert_ids: list[int],
) -> list[Alert]:
    if not alert_ids:
        return []

    alerts = (
        db.query(Alert)
        .filter(Alert.id.in_(alert_ids))
        .all()
    )

    found_ids = {alert.id for alert in alerts}
    missing = sorted(set(alert_ids) - found_ids)

    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alerts not found: {missing}",
        )

    return alerts


def _get_indicators_by_ids(
    db: Session,
    indicator_ids: list[int],
) -> list[Indicator]:
    if not indicator_ids:
        return []

    indicators = (
        db.query(Indicator)
        .filter(Indicator.id.in_(indicator_ids))
        .all()
    )

    found_ids = {
        indicator.id
        for indicator in indicators
    }
    missing = sorted(set(indicator_ids) - found_ids)

    if missing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Indicators not found: {missing}",
        )

    return indicators


def create_incident(
    db: Session,
    incident_data: IncidentCreate,
    created_by: int,
    *,
    commit: bool = True,
) -> Incident:
    _validate_assignee(
        db,
        incident_data.assigned_to,
    )

    alerts = _get_alerts_by_ids(
        db,
        incident_data.alert_ids,
    )
    indicators = _get_indicators_by_ids(
        db,
        incident_data.indicator_ids,
    )

    incident = Incident(
        title=incident_data.title,
        description=incident_data.description,
        priority=incident_data.priority,
        status=IncidentStatus.OPEN,
        created_by=created_by,
        assigned_to=incident_data.assigned_to,
    )

    incident.alerts = alerts
    incident.indicators = indicators

    db.add(incident)

    try:
        if commit:
            db.commit()
            db.refresh(incident)
        else:
            db.flush()

    except SQLAlchemyError:
        db.rollback()
        raise

    return incident


def get_incident_by_id(
    db: Session,
    incident_id: int,
) -> Incident | None:
    return (
        db.query(Incident)
        .filter(Incident.id == incident_id)
        .first()
    )


def get_incidents(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    incident_status: IncidentStatus | None = None,
    priority=None,
    assigned_to: int | None = None,
    search: str | None = None,
) -> list[Incident]:
    query = db.query(Incident)

    if incident_status is not None:
        query = query.filter(
            Incident.status == incident_status
        )

    if priority is not None:
        query = query.filter(
            Incident.priority == priority
        )

    if assigned_to is not None:
        query = query.filter(
            Incident.assigned_to == assigned_to
        )

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            or_(
                Incident.title.ilike(pattern),
                Incident.description.ilike(pattern),
            )
        )

    return (
        query
        .order_by(
            Incident.created_at.desc(),
            Incident.id.desc(),
        )
        .offset(skip)
        .limit(limit)
        .all()
    )


def update_incident(
    db: Session,
    incident: Incident,
    incident_data: IncidentUpdate,
    *,
    commit: bool = True,
) -> Incident:
    update_data = incident_data.model_dump(
        exclude_unset=True,
    )

    if "assigned_to" in update_data:
        _validate_assignee(
            db,
            update_data["assigned_to"],
        )

    if "status" in update_data:
        new_status = update_data["status"]

        if new_status == IncidentStatus.RESOLVED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Use the incident resolution endpoint "
                    "to resolve an incident."
                ),
            )

        if new_status == IncidentStatus.CLOSED:
            if incident.status != IncidentStatus.RESOLVED:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        "Only a resolved incident can be closed."
                    ),
                )

        if new_status in {
            IncidentStatus.OPEN,
            IncidentStatus.IN_PROGRESS,
        }:
            incident.resolved_at = None
            incident.resolution_type = None
            incident.resolution_summary = None
            incident.resolved_by = None

    for key, value in update_data.items():
        setattr(incident, key, value)

    try:
        if commit:
            db.commit()
            db.refresh(incident)
        else:
            db.flush()

    except SQLAlchemyError:
        db.rollback()
        raise

    return incident


def resolve_incident(
    db: Session,
    incident: Incident,
    resolution_data: IncidentResolve,
    resolved_by: int,
    *,
    commit: bool = True,
) -> Incident:
    if incident.status == IncidentStatus.CLOSED:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Closed incidents cannot be resolved again.",
        )

    resolver = (
        db.query(User)
        .filter(
            User.id == resolved_by,
            User.is_active.is_(True),
            User.role.in_(("admin", "analyst")),
        )
        .first()
    )

    if resolver is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resolver not found or inactive",
        )

    incident.status = IncidentStatus.RESOLVED
    incident.resolution_type = resolution_data.resolution_type
    incident.resolution_summary = (
        resolution_data.resolution_summary
    )
    incident.resolved_by = resolved_by
    incident.resolved_at = _utc_now()

    try:
        if commit:
            db.commit()
            db.refresh(incident)
        else:
            db.flush()

    except SQLAlchemyError:
        db.rollback()
        raise

    return incident

def delete_incident(
    db: Session,
    incident: Incident,
    *,
    commit: bool = True,
) -> None:
    db.delete(incident)

    try:
        if commit:
            db.commit()
        else:
            db.flush()

    except SQLAlchemyError:
        db.rollback()
        raise


def add_incident_note(
    db: Session,
    incident: Incident,
    note_data: IncidentNoteCreate,
    author_id: int,
    *,
    commit: bool = True,
) -> IncidentNote:
    note = IncidentNote(
        incident_id=incident.id,
        author_id=author_id,
        content=note_data.content,
    )

    db.add(note)

    try:
        if commit:
            db.commit()
            db.refresh(note)
        else:
            db.flush()

    except SQLAlchemyError:
        db.rollback()
        raise

    return note


def link_alert(
    db: Session,
    incident: Incident,
    alert_id: int,
    *,
    commit: bool = True,
) -> Incident:
    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    if alert not in incident.alerts:
        incident.alerts.append(alert)

    try:
        if commit:
            db.commit()
            db.refresh(incident)
        else:
            db.flush()

    except SQLAlchemyError:
        db.rollback()
        raise

    return incident


def unlink_alert(
    db: Session,
    incident: Incident,
    alert_id: int,
    *,
    commit: bool = True,
) -> Incident:
    alert = next(
        (
            item
            for item in incident.alerts
            if item.id == alert_id
        ),
        None,
    )

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert is not linked to this incident",
        )

    incident.alerts.remove(alert)

    try:
        if commit:
            db.commit()
            db.refresh(incident)
        else:
            db.flush()

    except SQLAlchemyError:
        db.rollback()
        raise

    return incident


def link_indicator(
    db: Session,
    incident: Incident,
    indicator_id: int,
    *,
    commit: bool = True,
) -> Incident:
    indicator = (
        db.query(Indicator)
        .filter(Indicator.id == indicator_id)
        .first()
    )

    if indicator is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat indicator not found",
        )

    if indicator not in incident.indicators:
        incident.indicators.append(indicator)

    try:
        if commit:
            db.commit()
            db.refresh(incident)
        else:
            db.flush()

    except SQLAlchemyError:
        db.rollback()
        raise

    return incident


def unlink_indicator(
    db: Session,
    incident: Incident,
    indicator_id: int,
    *,
    commit: bool = True,
) -> Incident:
    indicator = next(
        (
            item
            for item in incident.indicators
            if item.id == indicator_id
        ),
        None,
    )

    if indicator is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat indicator is not linked to this incident",
        )

    incident.indicators.remove(indicator)

    try:
        if commit:
            db.commit()
            db.refresh(incident)
        else:
            db.flush()

    except SQLAlchemyError:
        db.rollback()
        raise

    return incident
