from datetime import datetime, timedelta

from app.core.database import SessionLocal
from app.core.security import create_access_token
from app.models.audit import AuditEvent


def make_role_headers(
    user_id: int,
    email: str,
    role: str,
):
    token = create_access_token(
        data={
            "sub": str(user_id),
            "email": email,
            "role": role,
        }
    )

    return {
        "Authorization": f"Bearer {token}"
    }


def create_test_audit_events():
    db = SessionLocal()

    try:
        now = datetime.utcnow()

        events = [
            AuditEvent(
                action="TEST_CREATE",
                actor="pytest-admin",
                target="indicator-alpha",
                created_at=now - timedelta(minutes=3),
            ),
            AuditEvent(
                action="TEST_UPDATE",
                actor="pytest-analyst",
                target="indicator-beta",
                created_at=now - timedelta(minutes=2),
            ),
            AuditEvent(
                action="TEST_DELETE",
                actor="pytest-admin",
                target="indicator-gamma",
                created_at=now - timedelta(minutes=1),
            ),
        ]

        db.add_all(events)
        db.commit()

        for event in events:
            db.refresh(event)

        return [event.id for event in events]

    finally:
        db.close()


def delete_test_audit_events(event_ids):
    db = SessionLocal()

    try:
        db.query(AuditEvent).filter(
            AuditEvent.id.in_(event_ids)
        ).delete(
            synchronize_session=False
        )

        db.commit()

    finally:
        db.close()


def test_audit_events_requires_auth(client):
    response = client.get(
        "/admin/audit-events",
    )

    assert response.status_code == 401


def test_admin_can_list_audit_events(client):
    event_ids = create_test_audit_events()

    try:
        response = client.get(
            "/admin/audit-events?limit=100",
            headers=make_role_headers(
                1,
                "admin@threatlens.com",
                "admin",
            ),
        )

        assert response.status_code == 200

        data = response.json()

        returned_ids = {
            event["id"]
            for event in data
        }

        assert set(event_ids).issubset(returned_ids)

    finally:
        delete_test_audit_events(event_ids)


def test_analyst_cannot_list_audit_events(client):
    response = client.get(
        "/admin/audit-events",
        headers=make_role_headers(
            2,
            "analyst@threatlens.com",
            "analyst",
        ),
    )

    assert response.status_code == 403


def test_viewer_cannot_list_audit_events(client):
    response = client.get(
        "/admin/audit-events",
        headers=make_role_headers(
            3,
            "viewer@threatlens.com",
            "viewer",
        ),
    )

    assert response.status_code == 403


def test_audit_event_filters(client):
    event_ids = create_test_audit_events()

    try:
        response = client.get(
            "/admin/audit-events?action=TEST_UPDATE",
            headers=make_role_headers(
                1,
                "admin@threatlens.com",
                "admin",
            ),
        )

        assert response.status_code == 200

        data = response.json()

        assert len(data) == 1
        assert data[0]["action"] == "TEST_UPDATE"
        assert data[0]["actor"] == "pytest-analyst"
        assert data[0]["target"] == "indicator-beta"

    finally:
        delete_test_audit_events(event_ids)


def test_audit_event_pagination(client):
    event_ids = create_test_audit_events()

    try:
        response = client.get(
            "/admin/audit-events?limit=2&skip=1",
            headers=make_role_headers(
                1,
                "admin@threatlens.com",
                "admin",
            ),
        )

        assert response.status_code == 200

        data = response.json()

        assert len(data) == 2

    finally:
        delete_test_audit_events(event_ids)


def test_audit_events_are_newest_first(client):
    event_ids = create_test_audit_events()

    try:
        response = client.get(
            "/admin/audit-events?action=TEST_",
            headers=make_role_headers(
                1,
                "admin@threatlens.com",
                "admin",
            ),
        )

        assert response.status_code == 200

        data = response.json()

        timestamps = [
            event["created_at"]
            for event in data
        ]

        assert timestamps == sorted(
            timestamps,
            reverse=True,
        )

    finally:
        delete_test_audit_events(event_ids)
