from uuid import uuid4


def test_register_user(client):
    """
    Register a new user.
    """

    unique = uuid4().hex[:8]

    response = client.post(
        "/auth/register",
        json={
            "username": f"pytest_{unique}",
            "email": f"pytest_{unique}@example.com",
            "password": "Password123!",
        },
    )

    assert response.status_code in (200, 201)


def test_login_invalid_password(client):
    """
    Invalid login should fail.
    """

    response = client.post(
        "/auth/login",
        json={
            "email": "doesnotexist@example.com",
            "password": "wrongpassword",
        },
    )

    assert response.status_code == 401