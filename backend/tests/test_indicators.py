import pytest

from app.core.database import SessionLocal
from app.core.security import create_access_token
from app.threat_intel.models import Indicator

@pytest.fixture(autouse=True)
def clean_indicator_test_data():
    """
    Remove indicator records created by these tests
    before and after each test.
    """

    test_values = [
        "198.51.100.201",
        "198.51.100.202",
        "198.51.100.203",
    ]

    db = SessionLocal()

    try:
        db.query(Indicator).filter(
            Indicator.value.in_(test_values)
        ).delete(
            synchronize_session=False
        )

        db.commit()

        yield

    finally:
        db.query(Indicator).filter(
            Indicator.value.in_(test_values)
        ).delete(
            synchronize_session=False
        )

        db.commit()
        db.close()


# -------------------------------------------------
# Authentication Helper
# -------------------------------------------------

def make_admin_headers():
    """
    Create an admin JWT for indicator API tests.
    """

    token = create_access_token(
        data={
            "sub": "1",
            "email": "admin@threatlens.com",
            "role": "admin",
        }
    )

    return {
        "Authorization": f"Bearer {token}"
    }


# -------------------------------------------------
# Indicator Creation
# -------------------------------------------------

def test_create_indicator(client):
    """
    Verify that an indicator can be created successfully.
    """

    headers = make_admin_headers()

    response = client.post(
        "/indicators/",
        headers=headers,
        json={
            "indicator_type": "IP",
            "value": "198.51.100.201",
            "severity": "HIGH",
            "source": "pytest",
            "description": "Threat intelligence test indicator",
        },
    )

    assert response.status_code in (200, 201)

    data = response.json()

    assert data["value"] == "198.51.100.201"
    assert data["indicator_type"] == "IP"
    assert data["severity"] == "HIGH"
    assert data["source"] == "pytest"

    assert "threat_score" in data
    assert "reputation_score" in data


# -------------------------------------------------
# Indicator Retrieval
# -------------------------------------------------

def test_get_indicators(client):
    """
    Verify that stored indicators can be retrieved.
    """

    headers = make_admin_headers()

    response = client.get(
        "/indicators/",
        headers=headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert isinstance(data, list)


# -------------------------------------------------
# Duplicate Indicator Protection
# -------------------------------------------------

def test_duplicate_indicator_rejected(client):
    """
    Verify that the same indicator value cannot
    be inserted twice.
    """

    headers = make_admin_headers()

    value = "198.51.100.202"

    payload = {
        "indicator_type": "IP",
        "value": value,
        "severity": "HIGH",
        "source": "pytest",
        "description": "Duplicate indicator test",
    }

    first_response = client.post(
        "/indicators/",
        headers=headers,
        json=payload,
    )

    assert first_response.status_code in (200, 201)

    second_response = client.post(
        "/indicators/",
        headers=headers,
        json=payload,
    )

    assert second_response.status_code in (400, 409)


# -------------------------------------------------
# Unauthorized Indicator Creation
# -------------------------------------------------

def test_create_indicator_requires_auth(client):
    """
    Indicator creation must require authentication.
    """

    response = client.post(
        "/indicators/",
        json={
            "indicator_type": "IP",
            "value": "198.51.100.203",
            "severity": "HIGH",
            "source": "pytest",
            "description": "Unauthorized test",
        },
    )

    assert response.status_code == 401