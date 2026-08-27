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

def test_authenticated_request_rejects_malformed_sub(client):
    """
    JWTs with a non-numeric subject must be rejected cleanly.
    """

    from app.core.security import create_access_token

    token = create_access_token(
        {
            "sub": "not-a-number",
            "role": "admin",
        }
    )

    response = client.get(
        "/users/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Invalid or expired token"


def test_authenticated_request_rejects_nonexistent_user(client):
    """
    A valid JWT for a user ID that does not exist must be rejected.
    """

    from app.core.security import create_access_token

    token = create_access_token(
        {
            "sub": "999999999",
            "role": "admin",
        }
    )

    response = client.get(
        "/users/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Invalid or expired token"


def test_authenticated_request_rejects_inactive_user(client):
    """
    A valid JWT belonging to an inactive user must be rejected.
    """

    from app.core.database import SessionLocal
    from app.core.security import create_access_token, hash_password
    from app.models.user import User
    unique = uuid4().hex[:8]

    db = SessionLocal()

    try:
        inactive_user = User(
            username=f"inactive_{unique}",
            email=f"inactive_{unique}@example.com",
            hashed_password=hash_password("Password123!"),
            role="analyst",
            is_active=False,
        )

        db.add(inactive_user)
        db.commit()
        db.refresh(inactive_user)

        token = create_access_token(
            {
                "sub": str(inactive_user.id),
                "role": inactive_user.role,
            }
        )

    finally:
        db.close()

    response = client.get(
        "/users/me",
        headers={
            "Authorization": f"Bearer {token}",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Invalid or expired token"


def test_authenticated_request_accepts_active_user(client, admin_token):
    """
    A valid JWT for an active user must continue to authenticate.
    """

    response = client.get(
        "/users/me",
        headers={
            "Authorization": f"Bearer {admin_token}",
        },
    )

    assert response.status_code == 200
    assert response.json()["email"] == "admin@threatlens.com"
