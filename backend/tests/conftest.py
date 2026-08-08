import os

# -------------------------------------------------
# Test Environment
# -------------------------------------------------
# Must be configured before importing app.main
# so the application starts in test mode.
os.environ["APP_ENV"] = "test"


import pytest
from fastapi.testclient import TestClient

from app.main import app


# -------------------------------------------------
# Test Client
# -------------------------------------------------

@pytest.fixture(scope="session")
def client():
    """
    Shared TestClient for all tests.
    """

    with TestClient(app) as test_client:
        yield test_client


# -------------------------------------------------
# Admin Authentication
# -------------------------------------------------

@pytest.fixture(scope="session")
def admin_token(client):
    """
    Login using the existing admin account.
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