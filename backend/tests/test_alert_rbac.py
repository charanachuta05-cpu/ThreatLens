from app.core.security import create_access_token


# -------------------------------------------------
# Token Helpers
# -------------------------------------------------

def make_role_headers(user_id: int, email: str, role: str):
    """
    Create a JWT containing the requested role.
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
# Viewer RBAC
# -------------------------------------------------

def test_viewer_can_read_alerts(client):

    headers = make_role_headers(
        user_id=3,
        email="viewer@threatlens.com",
        role="viewer",
    )

    response = client.get(
        "/alerts/",
        headers=headers,
    )

    assert response.status_code == 200


def test_viewer_cannot_create_alert(client):

    headers = make_role_headers(
        user_id=3,
        email="viewer@threatlens.com",
        role="viewer",
    )

    response = client.post(
        "/alerts/",
        headers=headers,
        json={
            "title": "Viewer RBAC Test",
            "description": "Viewer should not create alerts.",
            "severity": "HIGH",
            "source": "pytest",
        },
    )

    assert response.status_code == 403


# -------------------------------------------------
# Analyst RBAC
# -------------------------------------------------

def test_analyst_can_read_alerts(client):

    headers = make_role_headers(
        user_id=2,
        email="analyst@threatlens.com",
        role="analyst",
    )

    response = client.get(
        "/alerts/",
        headers=headers,
    )

    assert response.status_code == 200


# -------------------------------------------------
# Admin RBAC
# -------------------------------------------------

def test_admin_can_read_alerts(client, admin_headers):

    response = client.get(
        "/alerts/",
        headers=admin_headers,
    )

    assert response.status_code == 200