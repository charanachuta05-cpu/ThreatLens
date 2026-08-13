from app.core.security import create_access_token


def auth_headers(user_id: int, email: str, role: str):
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


def test_high_risk_requires_auth(client):
    response = client.get(
        "/hunt/high-risk"
    )

    assert response.status_code == 401


def test_viewer_cannot_hunt(client):
    headers = auth_headers(
        3,
        "viewer@threatlens.com",
        "viewer",
    )

    response = client.get(
        "/hunt/high-risk",
        headers=headers,
    )

    assert response.status_code == 403


def test_analyst_can_hunt(client):
    headers = auth_headers(
        2,
        "analyst@threatlens.com",
        "analyst",
    )

    response = client.get(
        "/hunt/high-risk",
        headers=headers,
    )

    assert response.status_code == 200


def test_admin_can_hunt(client, admin_headers):
    response = client.get(
        "/hunt/high-risk",
        headers=admin_headers,
    )

    assert response.status_code == 200


def test_recent_limit_validation(
    client,
    admin_headers,
):
    response = client.get(
        "/hunt/recent?limit=0",
        headers=admin_headers,
    )

    assert response.status_code == 422


def test_recent_limit_upper_bound(
    client,
    admin_headers,
):
    response = client.get(
        "/hunt/recent?limit=101",
        headers=admin_headers,
    )

    assert response.status_code == 422


def test_recent_returns_hunt_schema(
    client,
    admin_headers,
):
    response = client.get(
        "/hunt/recent?limit=5",
        headers=admin_headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)

    if data:
        item = data[0]

        assert "id" in item
        assert "indicator_type" in item
        assert "value" in item
        assert "severity" in item
        assert "threat_score" in item
        assert "reputation_score" in item
        assert "source" in item
        assert "created_at" in item


def test_source_hunting_requires_auth(client):
    response = client.get(
        "/hunt/source/VirusTotal"
    )

    assert response.status_code == 401


def test_source_hunting_works_for_analyst(client):
    headers = auth_headers(
        2,
        "analyst@threatlens.com",
        "analyst",
    )

    response = client.get(
        "/hunt/source/VirusTotal",
        headers=headers,
    )

    assert response.status_code == 200
    assert isinstance(response.json(), list)
