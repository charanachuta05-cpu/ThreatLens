from app.core.security import create_access_token
from app.models.alert import Alert, AlertSeverity, AlertStatus

def create_test_alert(
    indicator_id: int,
    *,
    in_description: bool = True,
):
    db = SessionLocal()

    try:
        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.id == indicator_id,
            )
            .first()
        )

        if indicator is None:
            raise RuntimeError(
                "Test indicator does not exist."
            )

        if in_description:
            title = "Threat intelligence alert"
            description = (
                f"Observed indicator: {indicator.value}"
            )
        else:
            title = (
                f"Threat detected: {indicator.value}"
            )
            description = "Threat intelligence event"

        alert = Alert(
            title=title,
            description=description,
            severity=AlertSeverity.HIGH,
            status=AlertStatus.OPEN,
            source="pytest",
            created_by=1,
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert.id

    finally:
        db.close()

def delete_test_alert(alert_id: int):
    db = SessionLocal()

    try:
        db.query(Alert).filter(
            Alert.id == alert_id,
        ).delete(
            synchronize_session=False,
        )

        db.commit()

    finally:
        db.close()

def test_investigation_finds_alert_by_description(
    client,
    admin_headers,
):
    delete_test_indicator()

    indicator_id = create_test_indicator()
    alert_id = create_test_alert(
        indicator_id,
        in_description=True,
    )

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        alerts = response.json()["alerts"]

        assert any(
            alert["id"] == alert_id
            for alert in alerts
        )

    finally:
        delete_test_alert(alert_id)
        delete_test_indicator()


def test_investigation_finds_alert_by_title(
    client,
    admin_headers,
):
    delete_test_indicator()

    indicator_id = create_test_indicator()
    alert_id = create_test_alert(
        indicator_id,
        in_description=False,
    )

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        alerts = response.json()["alerts"]

        assert any(
            alert["id"] == alert_id
            for alert in alerts
        )

    finally:
        delete_test_alert(alert_id)
        delete_test_indicator()


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

def create_related_test_indicator(
    *,
    value: str,
    severity: str = "HIGH",
    source: str = "pytest",
    threat_score: int = 80,
    reputation_score: int = 45,
    confidence_score: int = 65,
    tags: str = "ip,high,high-risk",
):
    db = SessionLocal()

    try:
        indicator = Indicator(
            indicator_type="IP",
            value=value,
            severity=severity,
            source=source,
            description="Related investigation test indicator",
            threat_score=threat_score,
            reputation_score=reputation_score,
            confidence_score=confidence_score,
            tags=tags,
        )

        db.add(indicator)
        db.commit()
        db.refresh(indicator)

        return indicator.id

    finally:
        db.close()


def delete_indicator_by_value(value: str):
    db = SessionLocal()

    try:
        db.query(Indicator).filter(
            Indicator.value == value,
        ).delete(
            synchronize_session=False,
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

def test_investigation_returns_p2_recommendation(
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

        recommendation = response.json()[
            "recommendation"
        ]

        assert recommendation["priority"] == "P2"
        assert (
            recommendation["summary"]
            == "Monitor and validate."
        )
        assert (
            "Review recent activity"
            in recommendation["actions"]
        )

    finally:
        delete_test_indicator()


def test_investigation_returns_p1_for_critical_indicator(
    client,
    admin_headers,
):
    delete_test_indicator()

    db = SessionLocal()

    try:
        indicator = Indicator(
            indicator_type="IP",
            value="198.51.100.241",
            severity="CRITICAL",
            source="pytest",
            description="Critical investigation test",
            threat_score=10,
            reputation_score=10,
            confidence_score=10,
            tags="ip,critical",
        )

        db.add(indicator)
        db.commit()
        db.refresh(indicator)

        indicator_id = indicator.id

    finally:
        db.close()

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        recommendation = response.json()[
            "recommendation"
        ]

        assert recommendation["priority"] == "P1"
        assert (
            recommendation["summary"]
            == "Immediate investigation and containment required."
        )
        assert (
            "Block the indicator"
            in recommendation["actions"]
        )

    finally:
        delete_indicator_by_value(
            "198.51.100.241"
        )


def test_investigation_returns_p3_for_low_confidence(
    client,
    admin_headers,
):
    delete_test_indicator()

    db = SessionLocal()

    try:
        indicator = Indicator(
            indicator_type="IP",
            value="198.51.100.242",
            severity="HIGH",
            source="pytest",
            description="Low confidence investigation test",
            threat_score=90,
            reputation_score=40,
            confidence_score=20,
            tags="ip,high,high-risk",
        )

        db.add(indicator)
        db.commit()
        db.refresh(indicator)

        indicator_id = indicator.id

    finally:
        db.close()

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        recommendation = response.json()[
            "recommendation"
        ]

        assert recommendation["priority"] == "P3"
        assert (
            "limited confidence"
            in recommendation["summary"]
        )
        assert (
            "Validate the intelligence source"
            in recommendation["actions"]
        )

    finally:
        delete_indicator_by_value(
            "198.51.100.242"
        )


def test_investigation_returns_related_indicators(
    client,
    admin_headers,
):
    delete_test_indicator()

    primary_id = create_test_indicator()

    related_id = create_related_test_indicator(
        value="198.51.100.243",
    )

    try:
        response = client.get(
            f"/investigations/{primary_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        related = response.json()[
            "related_indicators"
        ]

        matched = next(
            (
                item
                for item in related
                if item["id"] == related_id
            ),
            None,
        )

        assert matched is not None
        assert (
            matched["value"]
            == "198.51.100.243"
        )
        assert matched["correlation_score"] >= 60
        assert matched["reasons"]

    finally:
        delete_indicator_by_value(
            "198.51.100.243"
        )
        delete_test_indicator()


def test_investigation_excludes_unrelated_indicators(
    client,
    admin_headers,
):
    delete_test_indicator()

    primary_id = create_test_indicator()

    unrelated_id = create_related_test_indicator(
        value="203.0.113.50",
        severity="LOW",
        source="different-source",
        reputation_score=100,
        confidence_score=0,
        tags="domain,benign",
    )

    try:
        response = client.get(
            f"/investigations/{primary_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        related = response.json()[
            "related_indicators"
        ]

        assert all(
            item["id"] != unrelated_id
            for item in related
        )

    finally:
        delete_indicator_by_value(
            "203.0.113.50"
        )
        delete_test_indicator()
