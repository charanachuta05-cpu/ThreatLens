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