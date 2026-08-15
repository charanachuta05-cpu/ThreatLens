from app.core.database import SessionLocal
from app.models.alert import Alert
from app.schemas.alert import AlertCreate
from app.services.alert_service import create_alert


def test_create_alert_flushes_without_committing():
    """
    create_alert() should flush the alert so that its ID is
    available, but leave transaction ownership to the caller.
    """

    db = SessionLocal()

    test_title = "Transaction Test Alert"

    try:
        db.query(Alert).filter(
            Alert.title == test_title
        ).delete(
            synchronize_session=False
        )

        db.commit()

        alert_data = AlertCreate(
            title=test_title,
            description="Transaction boundary test",
            severity="HIGH",
            source="pytest",
        )

        alert = create_alert(
            db=db,
            alert_data=alert_data,
            created_by=1,
            commit=False,
        )

        # flush() should populate the database-generated ID.
        assert alert.id is not None

        existing = (
            db.query(Alert)
            .filter(
                Alert.id == alert.id
            )
            .first()
        )

        assert existing is not None

        # create_alert() must not commit.
        # Rolling back here should remove the alert.
        db.rollback()

        rolled_back = (
            db.query(Alert)
            .filter(
                Alert.id == alert.id
            )
            .first()
        )

        assert rolled_back is None

    finally:
        db.rollback()

        db.query(Alert).filter(
            Alert.title == test_title
        ).delete(
            synchronize_session=False
        )

        db.commit()
        db.close()

def test_alert_and_audit_event_rollback_together():
    """
    Alert creation and its audit event must participate in the
    same transaction. Rolling back the transaction must remove
    both records.
    """

    from app.logging.audit import audit_event
    from app.models.audit import AuditEvent

    db = SessionLocal()

    test_title = "Atomic Audit Rollback Test"

    try:
        # Clean up any previous test data.
        db.query(Alert).filter(
            Alert.title == test_title
        ).delete(
            synchronize_session=False
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == "alert:atomic-test"
        ).delete(
            synchronize_session=False
        )

        db.commit()

        alert_data = AlertCreate(
            title=test_title,
            description="Atomic audit transaction test",
            severity="HIGH",
            source="pytest",
        )

        alert = create_alert(
            db=db,
            alert_data=alert_data,
            created_by=1,
            commit=False,
        )

        audit_event(
            db=db,
            action="CREATE_ALERT",
            actor="pytest-admin",
            target="alert:atomic-test",
        )

        assert alert.id is not None

        # Both records exist inside the current transaction.
        assert (
            db.query(Alert)
            .filter(Alert.id == alert.id)
            .first()
            is not None
        )

        assert (
            db.query(AuditEvent)
            .filter(
                AuditEvent.target == "alert:atomic-test"
            )
            .first()
            is not None
        )

        # Simulate transaction failure.
        db.rollback()

        # Neither record may survive the rollback.
        assert (
            db.query(Alert)
            .filter(Alert.id == alert.id)
            .first()
            is None
        )

        assert (
            db.query(AuditEvent)
            .filter(
                AuditEvent.target == "alert:atomic-test"
            )
            .first()
            is None
        )

    finally:
        db.rollback()

        db.query(Alert).filter(
            Alert.title == test_title
        ).delete(
            synchronize_session=False
        )

        db.query(AuditEvent).filter(
            AuditEvent.target == "alert:atomic-test"
        ).delete(
            synchronize_session=False
        )

        db.commit()
        db.close()
