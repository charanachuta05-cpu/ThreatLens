import pytest
from fastapi import HTTPException

from app.core.database import SessionLocal
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.models.incident import (
    Incident,
    IncidentNote,
    IncidentPriority,
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
from app.threat_intel.models import Indicator


TEST_TITLE = "Incident Service Test"
TEST_INDICATOR_VALUE = "198.51.100.245"


@pytest.fixture(autouse=True)
def clean_incident_service_data():
    def cleanup():
        db = SessionLocal()

        try:
            incidents = (
                db.query(Incident)
                .filter(Incident.title.like(f"{TEST_TITLE}%"))
                .all()
            )

            for incident in incidents:
                db.delete(incident)

            db.flush()

            indicator = (
                db.query(Indicator)
                .filter(
                    Indicator.value == TEST_INDICATOR_VALUE
                )
                .first()
            )

            if indicator is not None:
                db.query(Alert).filter(
                    Alert.indicator_id == indicator.id
                ).delete(
                    synchronize_session=False
                )

                db.delete(indicator)

            db.commit()

        finally:
            db.rollback()
            db.close()

    cleanup()
    yield
    cleanup()


def create_indicator(db):
    indicator = Indicator(
        indicator_type="IP",
        value=TEST_INDICATOR_VALUE,
        severity="HIGH",
        source="pytest",
        description="Incident service test indicator",
        threat_score=85,
        reputation_score=40,
        confidence_score=67,
        tags="ip,high,high-risk",
    )

    db.add(indicator)
    db.flush()

    return indicator


def create_alert(db, indicator_id):
    alert = Alert(
        title="Incident Service Linked Alert",
        description="Incident service linked alert",
        severity=AlertSeverity.HIGH,
        status=AlertStatus.OPEN,
        source="pytest",
        created_by=1,
        indicator_id=indicator_id,
    )

    db.add(alert)
    db.flush()

    return alert


def test_create_incident_flushes_without_commit():
    db = SessionLocal()

    try:
        data = IncidentCreate(
            title=f"{TEST_TITLE} Transaction",
            description="Transaction ownership test",
            priority=IncidentPriority.HIGH,
        )

        incident = create_incident(
            db=db,
            incident_data=data,
            created_by=1,
            commit=False,
        )

        assert incident.id is not None
        assert incident.status == IncidentStatus.OPEN

        incident_id = incident.id

        assert (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
            is not None
        )

        db.rollback()

        assert (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
            is None
        )

    finally:
        db.rollback()
        db.close()


def test_create_incident_with_links_and_assignee():
    db = SessionLocal()

    try:
        indicator = create_indicator(db)
        alert = create_alert(db, indicator.id)

        data = IncidentCreate(
            title=f"{TEST_TITLE} Linked",
            description="Linked resource test",
            priority=IncidentPriority.CRITICAL,
            assigned_to=2,
            alert_ids=[alert.id],
            indicator_ids=[indicator.id],
        )

        incident = create_incident(
            db=db,
            incident_data=data,
            created_by=1,
        )

        assert incident.id is not None
        assert incident.created_by == 1
        assert incident.assigned_to == 2
        assert incident.priority == IncidentPriority.CRITICAL
        assert incident.status == IncidentStatus.OPEN
        assert [item.id for item in incident.alerts] == [alert.id]
        assert [item.id for item in incident.indicators] == [
            indicator.id
        ]

    finally:
        db.rollback()
        db.close()


def test_create_incident_rejects_viewer_assignee():
    db = SessionLocal()

    try:
        viewer = (
            db.query(User)
            .filter(User.role == "viewer")
            .first()
        )

        assert viewer is not None

        data = IncidentCreate(
            title=f"{TEST_TITLE} Viewer Assignment",
            description="Viewer assignment must fail",
            assigned_to=viewer.id,
        )

        with pytest.raises(HTTPException) as exc:
            create_incident(
                db=db,
                incident_data=data,
                created_by=1,
            )

        assert exc.value.status_code == 404

    finally:
        db.rollback()
        db.close()


def test_create_incident_rejects_missing_resources():
    db = SessionLocal()

    try:
        data = IncidentCreate(
            title=f"{TEST_TITLE} Missing",
            description="Missing alert validation",
            alert_ids=[999999999],
        )

        with pytest.raises(HTTPException) as exc:
            create_incident(
                db=db,
                incident_data=data,
                created_by=1,
            )

        assert exc.value.status_code == 404

    finally:
        db.rollback()
        db.close()


def test_incident_resolution_lifecycle():
    db = SessionLocal()

    try:
        incident = create_incident(
            db=db,
            incident_data=IncidentCreate(
                title=f"{TEST_TITLE} Status",
                description="Status transition test",
            ),
            created_by=1,
        )

        with pytest.raises(HTTPException) as exc:
            update_incident(
                db=db,
                incident=incident,
                incident_data=IncidentUpdate(
                    status=IncidentStatus.RESOLVED,
                ),
            )

        assert exc.value.status_code == 400

        with pytest.raises(HTTPException) as exc:
            update_incident(
                db=db,
                incident=incident,
                incident_data=IncidentUpdate(
                    status=IncidentStatus.CLOSED,
                ),
            )

        assert exc.value.status_code == 400

        resolve_incident(
            db=db,
            incident=incident,
            resolution_data=IncidentResolve(
                resolution_type=(
                    IncidentResolutionType.TRUE_POSITIVE
                ),
                resolution_summary=(
                    "Confirmed malicious activity."
                ),
            ),
            resolved_by=2,
        )

        assert incident.status == IncidentStatus.RESOLVED
        assert (
            incident.resolution_type
            == IncidentResolutionType.TRUE_POSITIVE
        )
        assert (
            incident.resolution_summary
            == "Confirmed malicious activity."
        )
        assert incident.resolved_by == 2
        assert incident.resolved_at is not None

        update_incident(
            db=db,
            incident=incident,
            incident_data=IncidentUpdate(
                status=IncidentStatus.CLOSED,
            ),
        )

        assert incident.status == IncidentStatus.CLOSED
        assert incident.resolved_at is not None
        assert incident.resolved_by == 2

        update_incident(
            db=db,
            incident=incident,
            incident_data=IncidentUpdate(
                status=IncidentStatus.IN_PROGRESS,
            ),
        )

        assert incident.status == IncidentStatus.IN_PROGRESS
        assert incident.resolved_at is None
        assert incident.resolution_type is None
        assert incident.resolution_summary is None
        assert incident.resolved_by is None

    finally:
        db.rollback()
        db.close()


def test_add_incident_note():
    db = SessionLocal()

    try:
        incident = create_incident(
            db=db,
            incident_data=IncidentCreate(
                title=f"{TEST_TITLE} Note",
                description="Note test",
            ),
            created_by=1,
        )

        note = add_incident_note(
            db=db,
            incident=incident,
            note_data=IncidentNoteCreate(
                content="Analyst investigation started."
            ),
            author_id=2,
        )

        assert note.id is not None
        assert note.incident_id == incident.id
        assert note.author_id == 2
        assert note.content == "Analyst investigation started."

        stored = (
            db.query(IncidentNote)
            .filter(IncidentNote.id == note.id)
            .first()
        )

        assert stored is not None

    finally:
        db.rollback()
        db.close()


def test_link_and_unlink_alert():
    db = SessionLocal()

    try:
        indicator = create_indicator(db)
        alert = create_alert(db, indicator.id)

        incident = create_incident(
            db=db,
            incident_data=IncidentCreate(
                title=f"{TEST_TITLE} Alert Link",
                description="Alert relationship test",
            ),
            created_by=1,
        )

        link_alert(
            db=db,
            incident=incident,
            alert_id=alert.id,
        )

        assert alert.id in {
            item.id for item in incident.alerts
        }

        # Linking the same alert twice must remain idempotent.
        link_alert(
            db=db,
            incident=incident,
            alert_id=alert.id,
        )

        assert [
            item.id for item in incident.alerts
        ].count(alert.id) == 1

        unlink_alert(
            db=db,
            incident=incident,
            alert_id=alert.id,
        )

        assert alert.id not in {
            item.id for item in incident.alerts
        }

    finally:
        db.rollback()
        db.close()


def test_link_and_unlink_indicator():
    db = SessionLocal()

    try:
        indicator = create_indicator(db)

        incident = create_incident(
            db=db,
            incident_data=IncidentCreate(
                title=f"{TEST_TITLE} Indicator Link",
                description="Indicator relationship test",
            ),
            created_by=1,
        )

        link_indicator(
            db=db,
            incident=incident,
            indicator_id=indicator.id,
        )

        assert indicator.id in {
            item.id for item in incident.indicators
        }

        link_indicator(
            db=db,
            incident=incident,
            indicator_id=indicator.id,
        )

        assert [
            item.id for item in incident.indicators
        ].count(indicator.id) == 1

        unlink_indicator(
            db=db,
            incident=incident,
            indicator_id=indicator.id,
        )

        assert indicator.id not in {
            item.id for item in incident.indicators
        }

    finally:
        db.rollback()
        db.close()


def test_get_incident_and_filtered_list():
    db = SessionLocal()

    try:
        incident = create_incident(
            db=db,
            incident_data=IncidentCreate(
                title=f"{TEST_TITLE} Searchable",
                description="Unique incident search phrase",
                priority=IncidentPriority.HIGH,
                assigned_to=2,
            ),
            created_by=1,
        )

        fetched = get_incident_by_id(
            db,
            incident.id,
        )

        assert fetched is not None
        assert fetched.id == incident.id

        results = get_incidents(
            db,
            incident_status=IncidentStatus.OPEN,
            priority=IncidentPriority.HIGH,
            assigned_to=2,
            search="Searchable",
        )

        assert incident.id in {
            item.id for item in results
        }

    finally:
        db.rollback()
        db.close()


def test_delete_incident():
    db = SessionLocal()

    try:
        incident = create_incident(
            db=db,
            incident_data=IncidentCreate(
                title=f"{TEST_TITLE} Delete",
                description="Delete test",
            ),
            created_by=1,
        )

        incident_id = incident.id

        delete_incident(
            db=db,
            incident=incident,
        )

        assert get_incident_by_id(
            db,
            incident_id,
        ) is None

    finally:
        db.rollback()
        db.close()
