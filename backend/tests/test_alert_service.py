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