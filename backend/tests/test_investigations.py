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
from app.core.database import SessionLocal
from app.threat_intel.models import Indicator


TEST_INDICATOR_VALUE = "198.51.100.240"

EXPECTED_TAGS = [
    "ip",
    "high",
    "high-risk",
]


def create_test_indicator():
    db = SessionLocal()

    try:
        indicator = Indicator(
            indicator_type="IP",
            value=TEST_INDICATOR_VALUE,
            severity="HIGH",
            source="pytest",
            description="Investigation endpoint test indicator",
            threat_score=85,
            reputation_score=40,
            confidence_score=67,
            tags="ip,high,high-risk",
        )

        db.add(indicator)
        db.commit()
        db.refresh(indicator)

        return indicator.id

    finally:
        db.close()


def delete_test_indicator():
    db = SessionLocal()

    try:
        db.query(Indicator).filter(
            Indicator.value == TEST_INDICATOR_VALUE
        ).delete(
            synchronize_session=False
        )

        db.commit()

    finally:
        db.close()

def test_investigation_requires_auth(client):
    response = client.get(
        "/investigations/999999",
    )

    assert response.status_code == 401


def test_viewer_cannot_investigate(client):
    headers = make_role_headers(
        user_id=3,
        email="viewer@threatlens.com",
        role="viewer",
    )

    response = client.get(
        "/investigations/999999",
        headers=headers,
    )

    assert response.status_code == 403


def test_analyst_can_investigate(
    client,
    admin_headers,
):
    delete_test_indicator()

    indicator_id = create_test_indicator()

    try:
        headers = make_role_headers(
            user_id=2,
            email="analyst@threatlens.com",
            role="analyst",
        )

        response = client.get(
            f"/investigations/{indicator_id}",
            headers=headers,
        )

        assert response.status_code == 200

        data = response.json()

        assert data["indicator"]["id"] == indicator_id
        assert data["indicator"]["value"] == TEST_INDICATOR_VALUE

    finally:
        delete_test_indicator()


def test_admin_can_investigate(
    client,
    admin_headers,
):
    delete_test_indicator()

    indicator_id = create_test_indicator()

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

    finally:
        delete_test_indicator()


def test_investigation_returns_indicator(
    client,
    admin_headers,
):
    delete_test_indicator()

    indicator_id = create_test_indicator()

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        data = response.json()

        assert data["indicator"]["id"] == indicator_id
        assert data["indicator"]["value"] == TEST_INDICATOR_VALUE
        assert data["indicator"]["type"] == "IP"
        assert data["indicator"]["severity"] == "HIGH"
        assert data["indicator"]["source"] == "pytest"

    finally:
        delete_test_indicator()


def test_investigation_returns_persisted_scores(
    client,
    admin_headers,
):
    delete_test_indicator()

    indicator_id = create_test_indicator()

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        scores = response.json()["scores"]

        assert scores["threat_score"] == 85
        assert scores["reputation_score"] == 40
        assert scores["confidence_score"] == 67

    finally:
        delete_test_indicator()


def test_investigation_returns_persisted_tags(
    client,
    admin_headers,
):
    delete_test_indicator()

    indicator_id = create_test_indicator()

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        tags = response.json()["tags"]

        assert tags == EXPECTED_TAGS

    finally:
        delete_test_indicator()


def test_investigation_not_found(
    client,
    admin_headers,
):
    response = client.get(
        "/investigations/999999",
        headers=admin_headers,
    )

    assert response.status_code == 404

    data = response.json()

    assert data["success"] is False
    assert data["error"]["code"] == 404
    assert data["error"]["type"] == "HTTPException"
    assert data["error"]["message"] == "Indicator not found."