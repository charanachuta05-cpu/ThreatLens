from app.core.security import create_access_token


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


def test_assignable_users_requires_auth(client):
    response = client.get("/users/assignable")

    assert response.status_code == 401


def test_admin_can_get_assignable_users(
    client,
    admin_headers,
):
    response = client.get(
        "/users/assignable",
        headers=admin_headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)
    assert data

    for user in data:
        assert user["is_active"] is True
        assert user["role"] in ("admin", "analyst")
        assert set(user) == {
            "id",
            "username",
            "email",
            "role",
            "is_active",
            "created_at",
        }


def test_analyst_can_get_assignable_users(
    client,
):
    analyst_headers = make_role_headers(
        user_id=2,
        email="analyst@threatlens.com",
        role="analyst",
    )

    response = client.get(
        "/users/assignable",
        headers=analyst_headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)

    for user in data:
        assert user["is_active"] is True
        assert user["role"] in ("admin", "analyst")


def test_viewer_cannot_get_assignable_users(
    client,
):
    viewer_headers = make_role_headers(
        user_id=3,
        email="viewer@threatlens.com",
        role="viewer",
    )

    response = client.get(
        "/users/assignable",
        headers=viewer_headers,
    )

    assert response.status_code == 403
