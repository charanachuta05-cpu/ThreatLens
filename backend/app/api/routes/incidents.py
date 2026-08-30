from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.api.dependencies.auth import require_roles
from app.logging.audit import audit_event
from app.models.incident import IncidentPriority, IncidentStatus
from app.models.user import User
from app.schemas.incident import (
    IncidentCreate,
    IncidentNoteCreate,
    IncidentNoteResponse,
    IncidentResolve,
    IncidentResponse,
    IncidentUpdate,
)
from app.services.incident_service import (
    add_incident_note,
    create_incident,
    delete_incident,
    get_incident_by_id,
    get_incidents,
    link_alert,
    link_indicator,
    unlink_alert,
    unlink_indicator,
    update_incident,
    resolve_incident,
)


router = APIRouter(
    prefix="/incidents",
    tags=["Incidents"],
)


def _get_incident_or_404(
    db: Session,
    incident_id: int,
):
    incident = get_incident_by_id(
        db,
        incident_id,
    )

    if incident is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found",
        )

    return incident


@router.post(
    "/",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_new_incident(
    incident_data: IncidentCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    try:
        incident = create_incident(
            db=db,
            incident_data=incident_data,
            created_by=current_user.id,
            commit=False,
        )

        audit_event(
            db=db,
            action="CREATE_INCIDENT",
            actor=current_user.email,
            target=f"incident:{incident.id}",
        )

        db.commit()
        db.refresh(incident)

        return incident

    except Exception:
        db.rollback()
        raise


@router.get(
    "/",
    response_model=list[IncidentResponse],
)
def list_incidents(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    incident_status: IncidentStatus | None = Query(
        default=None,
        alias="status",
    ),
    priority: IncidentPriority | None = Query(default=None),
    assigned_to: int | None = Query(default=None, ge=1),
    search: str | None = Query(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    return get_incidents(
        db=db,
        skip=skip,
        limit=limit,
        incident_status=incident_status,
        priority=priority,
        assigned_to=assigned_to,
        search=search,
    )


@router.get(
    "/{incident_id}",
    response_model=IncidentResponse,
)
def read_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    return _get_incident_or_404(
        db,
        incident_id,
    )


@router.put(
    "/{incident_id}",
    response_model=IncidentResponse,
)
def update_existing_incident(
    incident_id: int,
    incident_data: IncidentUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    incident = _get_incident_or_404(
        db,
        incident_id,
    )

    changes = incident_data.model_dump(
        exclude_unset=True
    )

    try:
        updated = update_incident(
            db=db,
            incident=incident,
            incident_data=incident_data,
            commit=False,
        )

        if "assigned_to" in changes:
            action = "ASSIGN_INCIDENT"
        elif changes.get("status") == IncidentStatus.RESOLVED:
            action = "RESOLVE_INCIDENT"
        elif changes.get("status") == IncidentStatus.CLOSED:
            action = "CLOSE_INCIDENT"
        else:
            action = "UPDATE_INCIDENT"

        audit_event(
            db=db,
            action=action,
            actor=current_user.email,
            target=f"incident:{incident_id}",
        )

        db.commit()
        db.refresh(updated)

        return updated

    except Exception:
        db.rollback()
        raise


@router.post(
    "/{incident_id}/resolve",
    response_model=IncidentResponse,
)
def resolve_existing_incident(
    incident_id: int,
    resolution_data: IncidentResolve,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    incident = _get_incident_or_404(
        db,
        incident_id,
    )

    try:
        incident = resolve_incident(
            db=db,
            incident=incident,
            resolution_data=resolution_data,
            resolved_by=current_user.id,
            commit=False,
        )

        audit_event(
            db=db,
            action="RESOLVE_INCIDENT",
            actor=current_user.email,
            target=f"incident:{incident.id}",
        )

        db.commit()
        db.refresh(incident)

        return incident

    except Exception:
        db.rollback()
        raise


@router.delete(
    "/{incident_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_incident(
    incident_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin")
    ),
):
    incident = _get_incident_or_404(
        db,
        incident_id,
    )

    try:
        audit_event(
            db=db,
            action="DELETE_INCIDENT",
            actor=current_user.email,
            target=f"incident:{incident_id}",
        )

        delete_incident(
            db=db,
            incident=incident,
            commit=False,
        )

        db.commit()

    except Exception:
        db.rollback()
        raise


@router.post(
    "/{incident_id}/notes",
    response_model=IncidentNoteResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_incident_note(
    incident_id: int,
    note_data: IncidentNoteCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    incident = _get_incident_or_404(
        db,
        incident_id,
    )

    try:
        note = add_incident_note(
            db=db,
            incident=incident,
            note_data=note_data,
            author_id=current_user.id,
            commit=False,
        )

        audit_event(
            db=db,
            action="ADD_INCIDENT_NOTE",
            actor=current_user.email,
            target=f"incident:{incident_id}",
        )

        db.commit()
        db.refresh(note)

        return note

    except Exception:
        db.rollback()
        raise


@router.post(
    "/{incident_id}/alerts/{alert_id}",
    response_model=IncidentResponse,
)
def attach_alert(
    incident_id: int,
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    incident = _get_incident_or_404(
        db,
        incident_id,
    )

    try:
        incident = link_alert(
            db=db,
            incident=incident,
            alert_id=alert_id,
            commit=False,
        )

        audit_event(
            db=db,
            action="LINK_INCIDENT_ALERT",
            actor=current_user.email,
            target=f"incident:{incident_id}:alert:{alert_id}",
        )

        db.commit()
        db.refresh(incident)

        return incident

    except Exception:
        db.rollback()
        raise


@router.delete(
    "/{incident_id}/alerts/{alert_id}",
    response_model=IncidentResponse,
)
def detach_alert(
    incident_id: int,
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    incident = _get_incident_or_404(
        db,
        incident_id,
    )

    try:
        incident = unlink_alert(
            db=db,
            incident=incident,
            alert_id=alert_id,
            commit=False,
        )

        audit_event(
            db=db,
            action="UNLINK_INCIDENT_ALERT",
            actor=current_user.email,
            target=f"incident:{incident_id}:alert:{alert_id}",
        )

        db.commit()
        db.refresh(incident)

        return incident

    except Exception:
        db.rollback()
        raise


@router.post(
    "/{incident_id}/indicators/{indicator_id}",
    response_model=IncidentResponse,
)
def attach_indicator(
    incident_id: int,
    indicator_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    incident = _get_incident_or_404(
        db,
        incident_id,
    )

    try:
        incident = link_indicator(
            db=db,
            incident=incident,
            indicator_id=indicator_id,
            commit=False,
        )

        audit_event(
            db=db,
            action="LINK_INCIDENT_INDICATOR",
            actor=current_user.email,
            target=f"incident:{incident_id}:indicator:{indicator_id}",
        )

        db.commit()
        db.refresh(incident)

        return incident

    except Exception:
        db.rollback()
        raise


@router.delete(
    "/{incident_id}/indicators/{indicator_id}",
    response_model=IncidentResponse,
)
def detach_indicator(
    incident_id: int,
    indicator_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst")
    ),
):
    incident = _get_incident_or_404(
        db,
        incident_id,
    )

    try:
        incident = unlink_indicator(
            db=db,
            incident=incident,
            indicator_id=indicator_id,
            commit=False,
        )

        audit_event(
            db=db,
            action="UNLINK_INCIDENT_INDICATOR",
            actor=current_user.email,
            target=f"incident:{incident_id}:indicator:{indicator_id}",
        )

        db.commit()
        db.refresh(incident)

        return incident

    except Exception:
        db.rollback()
        raise
