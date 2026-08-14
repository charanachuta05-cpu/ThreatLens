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
        "198.51.100.204",
        "198.51.100.205",
        "198.51.100.206",
        "198.51.100.207",
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
# Role-Based Access Control
# -------------------------------------------------

def make_role_headers(
    user_id: int,
    email: str,
    role: str,
):
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


def test_viewer_cannot_create_indicator(client):
    """
    Viewer users must not create indicators.
    """

    headers = make_role_headers(
        user_id=3,
        email="viewer@threatlens.com",
        role="viewer",
    )

    response = client.post(
        "/indicators/",
        headers=headers,
        json={
            "indicator_type": "IP",
            "value": "198.51.100.204",
            "severity": "HIGH",
            "source": "pytest",
        },
    )

    assert response.status_code == 403


def test_analyst_can_create_indicator(client):
    """
    Analyst users may create indicators.
    """

    headers = make_role_headers(
        user_id=2,
        email="analyst@threatlens.com",
        role="analyst",
    )

    response = client.post(
        "/indicators/",
        headers=headers,
        json={
            "indicator_type": "IP",
            "value": "198.51.100.205",
            "severity": "HIGH",
            "source": "pytest",
        },
    )

    assert response.status_code in (200, 201)


def test_viewer_can_read_indicators(client):
    """
    Viewer users may read indicators.
    """

    headers = make_role_headers(
        user_id=3,
        email="viewer@threatlens.com",
        role="viewer",
    )

    response = client.get(
        "/indicators/",
        headers=headers,
    )

    assert response.status_code == 200


def test_get_indicators_requires_auth(client):
    """
    Indicator retrieval requires authentication.
    """

    response = client.get(
        "/indicators/",
    )

    assert response.status_code == 401

# -------------------------------------------------
# Query Validation
# -------------------------------------------------

def test_indicator_limit_lower_bound(client):
    headers = make_admin_headers()

    response = client.get(
        "/indicators/?limit=0",
        headers=headers,
    )

    assert response.status_code == 422


def test_indicator_limit_upper_bound(client):
    headers = make_admin_headers()

    response = client.get(
        "/indicators/?limit=101",
        headers=headers,
    )

    assert response.status_code == 422


def test_indicator_skip_lower_bound(client):
    headers = make_admin_headers()

    response = client.get(
        "/indicators/?skip=-1",
        headers=headers,
    )

    assert response.status_code == 422


def test_indicator_min_score_lower_bound(client):
    headers = make_admin_headers()

    response = client.get(
        "/indicators/?min_score=-1",
        headers=headers,
    )

    assert response.status_code == 422


def test_indicator_min_score_upper_bound(client):
    headers = make_admin_headers()

    response = client.get(
        "/indicators/?min_score=101",
        headers=headers,
    )

    assert response.status_code == 422


def test_indicator_invalid_sort_field(client):
    headers = make_admin_headers()

    response = client.get(
        "/indicators/?sort_by=invalid",
        headers=headers,
    )

    assert response.status_code == 400


def test_indicator_invalid_sort_order(client):
    headers = make_admin_headers()

    response = client.get(
        "/indicators/?order=invalid",
        headers=headers,
    )

    assert response.status_code == 400

# -------------------------------------------------
# Filtering
# -------------------------------------------------

def create_filter_test_indicators(client):
    headers = make_admin_headers()

    indicators = [
        {
            "indicator_type": "IP",
            "value": "198.51.100.204",
            "severity": "LOW",
            "source": "filter-source-a",
        },
        {
            "indicator_type": "IP",
            "value": "198.51.100.205",
            "severity": "HIGH",
            "source": "filter-source-b",
        },
        {
            "indicator_type": "IP",
            "value": "198.51.100.206",
            "severity": "CRITICAL",
            "source": "filter-source-a",
        },
    ]

    for payload in indicators:
        response = client.post(
            "/indicators/",
            headers=headers,
            json=payload,
        )

        assert response.status_code in (200, 201)


def test_indicator_search_filter(client):
    create_filter_test_indicators(client)

    headers = make_admin_headers()

    response = client.get(
        "/indicators/?search=198.51.100.205",
        headers=headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert any(
        item["value"] == "198.51.100.205"
        for item in data
    )


def test_indicator_severity_filter(client):
    create_filter_test_indicators(client)

    headers = make_admin_headers()

    response = client.get(
        "/indicators/?severity=HIGH",
        headers=headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert all(
        item["severity"] == "HIGH"
        for item in data
    )


def test_indicator_source_filter(client):
    create_filter_test_indicators(client)

    headers = make_admin_headers()

    response = client.get(
        "/indicators/?source=filter-source-a",
        headers=headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert all(
        "filter-source-a"
        in item["source"]
        for item in data
    )


def test_indicator_min_score_filter(client):
    create_filter_test_indicators(client)

    headers = make_admin_headers()

    response = client.get(
        "/indicators/?min_score=80",
        headers=headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert all(
        item["threat_score"] >= 80
        for item in data
    )


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