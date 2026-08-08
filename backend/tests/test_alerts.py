from uuid import uuid4


# -------------------------------------------------
# Unauthorized Access
# -------------------------------------------------

def test_get_alerts_requires_auth(client):

    response = client.get("/alerts/")

    assert response.status_code == 401


def test_get_invalid_alert_requires_auth(client):

    response = client.get("/alerts/999999")

    assert response.status_code == 401


def test_create_alert_without_auth(client):

    response = client.post(
        "/alerts/",
        json={
            "title": "Unauthorized Alert",
            "description": "Should fail",
            "severity": "HIGH",
            "source": "pytest",
        },
    )

    assert response.status_code == 401


# -------------------------------------------------
# Authenticated Admin Tests
# -------------------------------------------------

def test_get_alerts_authenticated(
    client,
    admin_headers,
):

    response = client.get(
        "/alerts/",
        headers=admin_headers,
    )

    assert response.status_code == 200

    assert isinstance(
        response.json(),
        list,
    )


def test_create_alert_authenticated(
    client,
    admin_headers,
):

    unique = uuid4().hex[:6]

    response = client.post(
        "/alerts/",
        headers=admin_headers,
        json={
            "title": f"Pytest Alert {unique}",
            "description": "Created during automated testing.",
            "severity": "HIGH",
            "source": "pytest",
        },
    )

    assert response.status_code in (
        200,
        201,
    )


def test_invalid_alert_returns_404(
    client,
    admin_headers,
):

    response = client.get(
        "/alerts/999999",
        headers=admin_headers,
    )

    assert response.status_code == 404