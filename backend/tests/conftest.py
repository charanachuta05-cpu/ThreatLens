import os

# -------------------------------------------------
# Test Environment
# -------------------------------------------------
# Must be configured before importing app.main
# so the application starts in test mode and uses
# the isolated PostgreSQL test database.
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = (
    "postgresql+psycopg://postgres:sql0777@127.0.0.1:5432/threatlens_test"
)


import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models.user import User


# -------------------------------------------------
# Test Database Seed
# -------------------------------------------------

@pytest.fixture(scope="session")
def seed_test_users():
    """
    Create deterministic authentication users in the
    isolated test database.

    These users are created only in threatlens_test.
    """

    db = SessionLocal()

    users = [
        {
            "username": "admin",
            "email": "admin@threatlens.com",
            "password": "ThreatLens123",
            "role": "admin",
        },
        {
            "username": "analyst",
            "email": "analyst@threatlens.com",
            "password": "ThreatLens123",
            "role": "analyst",
        },
        {
            "username": "viewer",
            "email": "viewer@threatlens.com",
            "password": "ThreatLens123",
            "role": "viewer",
        },
    ]

    try:
        for user_data in users:
            existing_user = (
                db.query(User)
                .filter(User.email == user_data["email"])
                .first()
            )

            if existing_user is None:
                db.add(
                    User(
                        username=user_data["username"],
                        email=user_data["email"],
                        hashed_password=hash_password(
                            user_data["password"]
                        ),
                        role=user_data["role"],
                        is_active=True,
                    )
                )

        db.commit()

    finally:
        db.close()


# -------------------------------------------------
# Test Client
# -------------------------------------------------

@pytest.fixture(scope="session")
def client(seed_test_users):
    """
    Shared TestClient for all tests.

    The test users are guaranteed to exist before
    the application client is created.
    """

    with TestClient(app) as test_client:
        yield test_client


# -------------------------------------------------
# Admin Authentication
# -------------------------------------------------

@pytest.fixture(scope="session")
def admin_token(client):
    """
    Login using the deterministic test admin account.
    """

    response = client.post(
        "/auth/login",
        json={
            "email": "admin@threatlens.com",
            "password": "ThreatLens123",
        },
    )

    assert response.status_code == 200

    return response.json()["access_token"]


# -------------------------------------------------
# Admin Authorization Headers
# -------------------------------------------------

@pytest.fixture(scope="session")
def admin_headers(admin_token):
    """
    Authorization header for authenticated admin requests.
    """

    return {
        "Authorization": f"Bearer {admin_token}"
    }