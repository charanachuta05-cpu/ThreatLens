from app.core.security import create_access_token


# -------------------------------------------------
# Authentication Helpers
# -------------------------------------------------

def make_role_headers(
    user_id: int,
    email: str,
    role: str,
):
    """
    Create JWT headers for a specific test role.
    """

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


# -------------------------------------------------
# Create Test Alert
# -------------------------------------------------

def create_test_alert(client, headers):
    """
    Create an alert and return its ID.
    """

    response = client.post(
        "/alerts/",
        headers=headers,
        json={
            "title": "RBAC Mutation Test Alert",
            "description": "Alert created for RBAC mutation testing.",
            "severity": "HIGH",
            "source": "pytest",
        },
    )

    assert response.status_code in (200, 201)

    return response.json()["id"]


# -------------------------------------------------
# Admin Update
# -------------------------------------------------

def test_admin_can_update_alert(client, admin_headers):

    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    response = client.put(
        f"/alerts/{alert_id}",
        headers=admin_headers,
        json={
            "title": "Updated RBAC Alert",
            "description": "Updated by admin.",
            "severity": "CRITICAL",
            "source": "pytest",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == alert_id
    assert data["title"] == "Updated RBAC Alert"
    assert data["severity"] == "CRITICAL"


# -------------------------------------------------
# Viewer Cannot Update
# -------------------------------------------------

def test_viewer_cannot_update_alert(client, admin_headers):

    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    viewer_headers = make_role_headers(
        user_id=3,
        email="viewer@threatlens.com",
        role="viewer",
    )

    response = client.put(
        f"/alerts/{alert_id}",
        headers=viewer_headers,
        json={
            "title": "Viewer Attempt",
            "description": "Viewer should not update.",
            "severity": "HIGH",
            "source": "pytest",
        },
    )

    assert response.status_code == 403


# -------------------------------------------------
# Admin Delete
# -------------------------------------------------

def test_admin_can_delete_alert(client, admin_headers):

    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    response = client.delete(
        f"/alerts/{alert_id}",
        headers=admin_headers,
    )

    assert response.status_code in (200, 204)

    verify = client.get(
        f"/alerts/{alert_id}",
        headers=admin_headers,
    )

    assert verify.status_code == 404


# -------------------------------------------------
# Viewer Cannot Delete
# -------------------------------------------------

def test_viewer_cannot_delete_alert(client, admin_headers):

    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    viewer_headers = make_role_headers(
        user_id=3,
        email="viewer@threatlens.com",
        role="viewer",
    )

    response = client.delete(
        f"/alerts/{alert_id}",
        headers=viewer_headers,
    )

    assert response.status_code == 403

# -------------------------------------------------
# Invalid Assigned User
# -------------------------------------------------

def test_invalid_assigned_user_rejected(
    client,
    admin_headers,
):
    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    response = client.put(
        f"/alerts/{alert_id}",
        headers=admin_headers,
        json={
            "assigned_to": 999999,
        },
    )

    assert response.status_code == 404

    data = response.json()

    assert data["success"] is False
    assert (
        data["error"]["message"]
        == "Assigned user not found or inactive"
    )


# -------------------------------------------------
# Zero Assigned User
# -------------------------------------------------

def test_zero_assigned_user_rejected(
    client,
    admin_headers,
):
    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    response = client.put(
        f"/alerts/{alert_id}",
        headers=admin_headers,
        json={
            "assigned_to": 0,
        },
    )

    assert response.status_code == 422

# -------------------------------------------------
# Valid Assigned User
# -------------------------------------------------

def test_admin_can_assign_alert(
    client,
    admin_headers,
):
    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    response = client.put(
        f"/alerts/{alert_id}",
        headers=admin_headers,
        json={
            "assigned_to": 1,
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["id"] == alert_id
    assert data["assigned_to"] == 1

# -------------------------------------------------
# Clear Alert Assignment
# -------------------------------------------------

def test_admin_can_clear_alert_assignment(
    client,
    admin_headers,
):
    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    assign_response = client.put(
        f"/alerts/{alert_id}",
        headers=admin_headers,
        json={
            "assigned_to": 1,
        },
    )

    assert assign_response.status_code == 200

    clear_response = client.put(
        f"/alerts/{alert_id}",
        headers=admin_headers,
        json={
            "assigned_to": None,
        },
    )

    assert clear_response.status_code == 200

    data = clear_response.json()

    assert data["id"] == alert_id
    assert data["assigned_to"] is None

# -------------------------------------------------
# Invalid Alert Status
# -------------------------------------------------

def test_invalid_alert_status_rejected(
    client,
    admin_headers,
):
    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    response = client.put(
        f"/alerts/{alert_id}",
        headers=admin_headers,
        json={
            "status": "ACKNOWLEDGED",
        },
    )

    assert response.status_code == 422

# -------------------------------------------------
# Audit Event Verification
# -------------------------------------------------

def get_audit_events_for_target(target):
    from app.core.database import SessionLocal
    from app.models.audit import AuditEvent

    db = SessionLocal()

    try:
        return (
            db.query(AuditEvent)
            .filter(AuditEvent.target == target)
            .order_by(AuditEvent.id.desc())
            .all()
        )
    finally:
        db.close()


def test_create_alert_records_audit_event(
    client,
    admin_headers,
):
    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    events = get_audit_events_for_target(
        f"alert:{alert_id}"
    )

    try:
        assert any(
            event.action == "CREATE_ALERT"
            for event in events
        )
        assert any(
            event.target == f"alert:{alert_id}"
            for event in events
        )
    finally:
        from app.core.database import SessionLocal
        from app.models.audit import AuditEvent

        db = SessionLocal()

        try:
            db.query(AuditEvent).filter(
                AuditEvent.target == f"alert:{alert_id}"
            ).delete(
                synchronize_session=False
            )
            db.commit()
        finally:
            db.close()


def test_update_alert_records_audit_event(
    client,
    admin_headers,
):
    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    response = client.put(
        f"/alerts/{alert_id}",
        headers=admin_headers,
        json={
            "title": "Audited Update",
        },
    )

    assert response.status_code == 200

    events = get_audit_events_for_target(
        f"alert:{alert_id}"
    )

    try:
        assert any(
            event.action == "UPDATE_ALERT"
            for event in events
        )
    finally:
        from app.core.database import SessionLocal
        from app.models.audit import AuditEvent

        db = SessionLocal()

        try:
            db.query(AuditEvent).filter(
                AuditEvent.target == f"alert:{alert_id}"
            ).delete(
                synchronize_session=False
            )
            db.commit()
        finally:
            db.close()


def test_delete_alert_records_audit_event(
    client,
    admin_headers,
):
    alert_id = create_test_alert(
        client,
        admin_headers,
    )

    response = client.delete(
        f"/alerts/{alert_id}",
        headers=admin_headers,
    )

    assert response.status_code in (200, 204)

    events = get_audit_events_for_target(
        f"alert:{alert_id}"
    )

    try:
        assert any(
            event.action == "DELETE_ALERT"
            for event in events
        )
    finally:
        from app.core.database import SessionLocal
        from app.models.audit import AuditEvent

        db = SessionLocal()

        try:
            db.query(AuditEvent).filter(
                AuditEvent.target == f"alert:{alert_id}"
            ).delete(
                synchronize_session=False
            )
            db.commit()
        finally:
            db.close()
