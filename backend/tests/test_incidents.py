import pytest

from app.core.database import SessionLocal
from app.core.security import create_access_token
from app.models.audit import AuditEvent
from app.models.incident import Incident


TEST_PREFIX = "Incident API Test"


def make_headers(
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


@pytest.fixture(autouse=True)
def clean_incident_api_data():
    def cleanup():
        db = SessionLocal()

        try:
            incidents = (
                db.query(Incident)
                .filter(
                    Incident.title.like(
                        f"{TEST_PREFIX}%"
                    )
                )
                .all()
            )

            incident_ids = [
                incident.id
                for incident in incidents
            ]

            for incident in incidents:
                db.delete(incident)

            if incident_ids:
                targets = [
                    f"incident:{incident_id}"
                    for incident_id in incident_ids
                ]

                db.query(AuditEvent).filter(
                    AuditEvent.target.in_(targets)
                ).delete(
                    synchronize_session=False
                )

            db.commit()

        finally:
            db.rollback()
            db.close()

    cleanup()
    yield
    cleanup()


def test_incidents_require_auth(client):
    response = client.get("/incidents/")

    assert response.status_code == 401


def test_viewer_cannot_access_incidents(client):
    headers = make_headers(
        3,
        "viewer@threatlens.com",
        "viewer",
    )

    response = client.get(
        "/incidents/",
        headers=headers,
    )

    assert response.status_code == 403


def test_admin_can_create_incident(client):
    headers = make_headers(
        1,
        "admin@threatlens.com",
        "admin",
    )

    response = client.post(
        "/incidents/",
        headers=headers,
        json={
            "title": f"{TEST_PREFIX} Create",
            "description": "Created by API test",
            "priority": "HIGH",
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["title"] == f"{TEST_PREFIX} Create"
    assert data["priority"] == "HIGH"
    assert data["status"] == "OPEN"
    assert data["created_by"] == 1


def test_analyst_can_create_incident(client):
    headers = make_headers(
        2,
        "analyst@threatlens.com",
        "analyst",
    )

    response = client.post(
        "/incidents/",
        headers=headers,
        json={
            "title": f"{TEST_PREFIX} Analyst",
            "description": "Analyst incident",
            "priority": "MEDIUM",
        },
    )

    assert response.status_code == 201
    assert response.json()["created_by"] == 2


def test_create_incident_records_audit_event(client):
    headers = make_headers(
        1,
        "admin@threatlens.com",
        "admin",
    )

    response = client.post(
        "/incidents/",
        headers=headers,
        json={
            "title": f"{TEST_PREFIX} Audit",
            "description": "Audit test",
            "priority": "HIGH",
        },
    )

    assert response.status_code == 201

    incident_id = response.json()["id"]

    db = SessionLocal()

    try:
        event = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.action
                == "CREATE_INCIDENT",
                AuditEvent.target
                == f"incident:{incident_id}",
            )
            .first()
        )

        assert event is not None
        assert event.actor == "admin@threatlens.com"

    finally:
        db.close()


def test_admin_can_list_and_read_incident(client):
    headers = make_headers(
        1,
        "admin@threatlens.com",
        "admin",
    )

    created = client.post(
        "/incidents/",
        headers=headers,
        json={
            "title": f"{TEST_PREFIX} Read",
            "description": "Read/list test",
            "priority": "CRITICAL",
        },
    )

    assert created.status_code == 201

    incident_id = created.json()["id"]

    response = client.get(
        f"/incidents/{incident_id}",
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["id"] == incident_id

    response = client.get(
        "/incidents/?priority=CRITICAL"
        "&status=OPEN"
        "&search=Read",
        headers=headers,
    )

    assert response.status_code == 200
    assert incident_id in {
        item["id"]
        for item in response.json()
    }


def test_analyst_can_resolve_incident(client):
    headers = make_headers(
        2,
        "analyst@threatlens.com",
        "analyst",
    )

    created = client.post(
        "/incidents/",
        headers=headers,
        json={
            "title": f"{TEST_PREFIX} Resolve",
            "description": "Resolve test",
        },
    )

    assert created.status_code == 201
    incident_id = created.json()["id"]

    direct = client.put(
        f"/incidents/{incident_id}",
        headers=headers,
        json={
            "status": "RESOLVED",
        },
    )

    assert direct.status_code == 400

    premature_close = client.put(
        f"/incidents/{incident_id}",
        headers=headers,
        json={
            "status": "CLOSED",
        },
    )

    assert premature_close.status_code == 400

    response = client.post(
        f"/incidents/{incident_id}/resolve",
        headers=headers,
        json={
            "resolution_type": "TRUE_POSITIVE",
            "resolution_summary": (
                "Confirmed malicious activity "
                "after analyst investigation."
            ),
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "RESOLVED"
    assert data["resolution_type"] == "TRUE_POSITIVE"
    assert data["resolution_summary"] == (
        "Confirmed malicious activity "
        "after analyst investigation."
    )
    assert data["resolved_by"] == 2
    assert data["resolved_at"] is not None

    closed = client.put(
        f"/incidents/{incident_id}",
        headers=headers,
        json={
            "status": "CLOSED",
            "priority": "HIGH",
        },
    )

    assert closed.status_code == 200
    assert closed.json()["status"] == "CLOSED"
    assert closed.json()["priority"] == "HIGH"
    assert closed.json()["resolution_type"] == "TRUE_POSITIVE"
    assert closed.json()["resolved_by"] == 2

    reopened = client.put(
        f"/incidents/{incident_id}",
        headers=headers,
        json={
            "status": "IN_PROGRESS",
        },
    )

    assert reopened.status_code == 200

    reopened_data = reopened.json()

    assert reopened_data["status"] == "IN_PROGRESS"
    assert reopened_data["resolved_at"] is None
    assert reopened_data["resolution_type"] is None
    assert reopened_data["resolution_summary"] is None
    assert reopened_data["resolved_by"] is None


def test_resolve_incident_records_audit_event(client):
    headers = make_headers(
        2,
        "analyst@threatlens.com",
        "analyst",
    )

    created = client.post(
        "/incidents/",
        headers=headers,
        json={
            "title": f"{TEST_PREFIX} Resolution Audit",
            "description": "Resolution audit test",
        },
    )

    assert created.status_code == 201
    incident_id = created.json()["id"]

    response = client.post(
        f"/incidents/{incident_id}/resolve",
        headers=headers,
        json={
            "resolution_type": "FALSE_POSITIVE",
            "resolution_summary": (
                "Investigation determined the "
                "activity was a false positive."
            ),
        },
    )

    assert response.status_code == 200

    from app.core.database import SessionLocal
    from app.models.audit import AuditEvent

    db = SessionLocal()

    try:
        event = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.action == "RESOLVE_INCIDENT",
                AuditEvent.target == f"incident:{incident_id}",
            )
            .order_by(AuditEvent.id.desc())
            .first()
        )

        assert event is not None
        assert event.actor == "analyst@threatlens.com"

    finally:
        db.close()


def test_analyst_can_add_note(client):
    headers = make_headers(
        2,
        "analyst@threatlens.com",
        "analyst",
    )

    created = client.post(
        "/incidents/",
        headers=headers,
        json={
            "title": f"{TEST_PREFIX} Note",
            "description": "Note API test",
        },
    )

    incident_id = created.json()["id"]

    response = client.post(
        f"/incidents/{incident_id}/notes",
        headers=headers,
        json={
            "content": "Investigation started."
        },
    )

    assert response.status_code == 201

    data = response.json()

    assert data["incident_id"] == incident_id
    assert data["author_id"] == 2
    assert data["content"] == "Investigation started."


def test_analyst_cannot_delete_incident(client):
    admin_headers = make_headers(
        1,
        "admin@threatlens.com",
        "admin",
    )

    analyst_headers = make_headers(
        2,
        "analyst@threatlens.com",
        "analyst",
    )

    created = client.post(
        "/incidents/",
        headers=admin_headers,
        json={
            "title": f"{TEST_PREFIX} Protected Delete",
            "description": "Delete RBAC test",
        },
    )

    incident_id = created.json()["id"]

    response = client.delete(
        f"/incidents/{incident_id}",
        headers=analyst_headers,
    )

    assert response.status_code == 403


def test_admin_can_delete_incident(client):
    headers = make_headers(
        1,
        "admin@threatlens.com",
        "admin",
    )

    created = client.post(
        "/incidents/",
        headers=headers,
        json={
            "title": f"{TEST_PREFIX} Delete",
            "description": "Delete API test",
        },
    )

    incident_id = created.json()["id"]

    response = client.delete(
        f"/incidents/{incident_id}",
        headers=headers,
    )

    assert response.status_code == 204

    response = client.get(
        f"/incidents/{incident_id}",
        headers=headers,
    )

    assert response.status_code == 404
