# -------------------------------------------------
# Dashboard Authentication
# -------------------------------------------------


def test_dashboard_requires_auth(client):
    response = client.get(
        "/dashboard/summary"
    )

    assert response.status_code == 401


# -------------------------------------------------
# Dashboard RBAC
# -------------------------------------------------


def test_viewer_can_read_dashboard(
    client,
):
    from app.core.security import create_access_token

    token = create_access_token(
        data={
            "sub": "3",
            "email": "viewer@threatlens.com",
            "role": "viewer",
        }
    )

    response = client.get(
        "/dashboard/summary",
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 200


def test_analyst_can_read_dashboard(
    client,
):
    from app.core.security import create_access_token

    token = create_access_token(
        data={
            "sub": "2",
            "email": "analyst@threatlens.com",
            "role": "analyst",
        }
    )

    response = client.get(
        "/dashboard/summary",
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 200


def test_admin_can_read_dashboard(
    client,
    admin_headers,
):
    response = client.get(
        "/dashboard/summary",
        headers=admin_headers,
    )

    assert response.status_code == 200


# -------------------------------------------------
# Dashboard Response
# -------------------------------------------------


def test_dashboard_returns_expected_fields(
    client,
    admin_headers,
):
    response = client.get(
        "/dashboard/summary",
        headers=admin_headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert "total_indicators" in data
    assert "critical_indicators" in data
    assert "high_indicators" in data
    assert "active_alerts" in data
    assert "average_threat_score" in data

    assert isinstance(
        data["total_indicators"],
        int,
    )

    assert isinstance(
        data["critical_indicators"],
        int,
    )

    assert isinstance(
        data["high_indicators"],
        int,
    )

    assert isinstance(
        data["active_alerts"],
        int,
    )

    assert isinstance(
        data["average_threat_score"],
        (int, float),
    )