import pytest

from app.core.database import SessionLocal
from app.core.security import create_access_token
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.threat_intel.models import Indicator


TEST_INDICATOR_VALUE = "198.51.100.240"

EXPECTED_TAGS = [
    "ip",
    "high",
    "high-risk",
]


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


def delete_alerts_for_indicator(
    db,
    indicator_id: int,
):
    """
    Delete alerts directly associated with an indicator.

    The alerts.indicator_id foreign key means alerts must be
    removed before their parent indicator can be deleted.
    """

    db.query(Alert).filter(
        Alert.indicator_id == indicator_id,
    ).delete(
        synchronize_session=False,
    )


def delete_test_indicator():
    """
    Remove the investigation test indicator and any alerts
    referencing it.

    This helper is intentionally FK-aware.
    """

    db = SessionLocal()

    try:
        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value == TEST_INDICATOR_VALUE,
            )
            .first()
        )

        if indicator is not None:
            delete_alerts_for_indicator(
                db,
                indicator.id,
            )

            db.delete(indicator)

        db.commit()

    finally:
        db.rollback()
        db.close()


def delete_indicator_by_value(
    value: str,
):
    """
    Remove an indicator and its directly linked alerts.
    """

    db = SessionLocal()

    try:
        indicator = (
            db.query(Indicator)
            .filter(
                Indicator.value == value,
            )
            .first()
        )

        if indicator is not None:
            delete_alerts_for_indicator(
                db,
                indicator.id,
            )

            db.delete(indicator)

        db.commit()

    finally:
        db.rollback()
        db.close()


def create_test_indicator(
    *,
    value: str = TEST_INDICATOR_VALUE,
    indicator_type: str = "IP",
    severity: str = "HIGH",
    source: str = "pytest",
    threat_score: int = 85,
    reputation_score: int = 40,
    confidence_score: int = 67,
    tags: str = "ip,high,high-risk",
):
    db = SessionLocal()

    try:
        indicator = Indicator(
            indicator_type=indicator_type,
            value=value,
            severity=severity,
            source=source,
            description="Investigation endpoint test indicator",
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
    """
    Create a secondary indicator used by correlation tests.
    """

    delete_indicator_by_value(value)

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
        db.rollback()
        db.close()


def create_test_alert(
    indicator_id: int,
    *,
    in_description: bool = True,
):
    """
    Create an alert associated with the test indicator.

    The alert is deliberately linked through indicator_id so
    investigation tests exercise the real relationship.
    """

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
            indicator_id=indicator_id,
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        return alert.id

    finally:
        db.rollback()
        db.close()


def delete_test_alert(
    alert_id: int,
):
    """
    Delete an individual test alert.
    """

    db = SessionLocal()

    try:
        db.query(Alert).filter(
            Alert.id == alert_id,
        ).delete(
            synchronize_session=False,
        )

        db.commit()

    finally:
        db.rollback()
        db.close()


def test_investigation_requires_auth(
    client,
):
    response = client.get(
        "/investigations/999999",
    )

    assert response.status_code == 401


def test_viewer_cannot_investigate(
    client,
):
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


@pytest.mark.parametrize(
    (
        "user_id",
        "email",
        "role",
        "expected_status",
    ),
    [
        (
            1,
            "admin@threatlens.com",
            "admin",
            200,
        ),
        (
            2,
            "analyst@threatlens.com",
            "analyst",
            200,
        ),
        (
            3,
            "viewer@threatlens.com",
            "viewer",
            403,
        ),
    ],
)
def test_investigation_rbac_all_roles(
    client,
    user_id,
    email,
    role,
    expected_status,
):
    indicator_id = create_test_indicator()

    try:
        headers = make_role_headers(
            user_id=user_id,
            email=email,
            role=role,
        )

        response = client.get(
            f"/investigations/{indicator_id}",
            headers=headers,
        )

        assert response.status_code == expected_status

        if role in {"admin", "analyst"}:
            data = response.json()

            assert data["indicator"]["id"] == indicator_id
            assert (
                data["indicator"]["value"]
                == TEST_INDICATOR_VALUE
            )

        else:
            data = response.json()

            assert data["success"] is False
            assert data["error"]["code"] == 403

    finally:
        delete_test_indicator()


def test_analyst_can_investigate(
    client,
):
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
        assert (
            data["indicator"]["value"]
            == TEST_INDICATOR_VALUE
        )

    finally:
        delete_test_indicator()


def test_admin_can_investigate(
    client,
    admin_headers,
):
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
    indicator_id = create_test_indicator()

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        data = response.json()

        assert data["indicator"] == {
            "id": indicator_id,
            "value": TEST_INDICATOR_VALUE,
            "type": "IP",
            "severity": "HIGH",
            "source": "pytest",
        }

    finally:
        delete_test_indicator()


def test_investigation_returns_scores(
    client,
    admin_headers,
):
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


def test_investigation_returns_tags(
    client,
    admin_headers,
):
    indicator_id = create_test_indicator()

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        assert (
            response.json()["tags"]
            == EXPECTED_TAGS
        )

    finally:
        delete_test_indicator()


def test_investigation_finds_alert_by_description(
    client,
    admin_headers,
):
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


def test_investigation_alerts_are_newest_first(
    client,
    admin_headers,
):
    indicator_id = create_test_indicator()

    first_alert = create_test_alert(
        indicator_id,
        in_description=True,
    )

    second_alert = create_test_alert(
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

        ids = [
            alert["id"]
            for alert in alerts
        ]

        assert second_alert in ids
        assert first_alert in ids

        assert ids.index(second_alert) < ids.index(
            first_alert
        )

    finally:
        delete_test_alert(first_alert)
        delete_test_alert(second_alert)
        delete_test_indicator()


def test_investigation_returns_empty_related_indicators_when_none_match(
    client,
    admin_headers,
):
    """
    An isolated investigation indicator must not acquire
    unrelated indicators from other tests.

    The isolated indicator is deliberately constructed so that
    it cannot reach the correlation threshold against the normal
    IP/HIGH/pytest indicators used elsewhere in the test suite.
    """

    isolated_value = "192.0.2.240"

    delete_indicator_by_value(
        isolated_value,
    )

    indicator_id = create_test_indicator(
        value=isolated_value,
        indicator_type="DOMAIN",
        severity="LOW",
        source="isolated-test",
        threat_score=10,
        reputation_score=0,
        confidence_score=0,
        tags="",
    )

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        data = response.json()

        assert data["related_indicators"] == []

    finally:
        delete_indicator_by_value(
            isolated_value,
        )


def test_investigation_finds_related_indicator(
    client,
    admin_headers,
):
    related_value = "198.51.100.241"

    delete_indicator_by_value(
        related_value
    )

    indicator_id = create_test_indicator()

    related_id = create_related_test_indicator(
        value=related_value,
    )

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        related = response.json()[
            "related_indicators"
        ]

        assert any(
            item["id"] == related_id
            for item in related
        )

        matching = next(
            item
            for item in related
            if item["id"] == related_id
        )

        assert (
            matching["value"]
            == related_value
        )
        assert (
            matching["indicator_type"]
            == "IP"
        )
        assert matching["severity"] == "HIGH"
        assert (
            0
            <= matching["correlation_score"]
            <= 100
        )
        assert matching["reasons"]

    finally:
        delete_test_indicator()
        delete_indicator_by_value(
            related_value
        )


def test_investigation_related_indicators_are_sorted(
    client,
    admin_headers,
):
    related_values = [
        "198.51.100.242",
        "198.51.100.243",
    ]

    for value in related_values:
        delete_indicator_by_value(value)

    indicator_id = create_test_indicator()

    first_related_id = create_related_test_indicator(
        value=related_values[0],
    )

    second_related_id = create_related_test_indicator(
        value=related_values[1],
    )

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        related = response.json()[
            "related_indicators"
        ]

        scores = [
            item["correlation_score"]
            for item in related
        ]

        assert scores == sorted(
            scores,
            reverse=True,
        )

        ids = [
            item["id"]
            for item in related
        ]

        assert first_related_id in ids
        assert second_related_id in ids

    finally:
        delete_test_indicator()

        for value in related_values:
            delete_indicator_by_value(value)

def test_investigation_returns_explanation(
    client,
    admin_headers,
):
    indicator_id = create_test_indicator()

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        explanation = response.json()["explanation"]

        assert explanation["threat_score"]["value"] == 85
        assert explanation["reputation_score"]["value"] == 40
        assert explanation["confidence_score"]["value"] == 67

    finally:
        delete_test_indicator()


def test_investigation_explains_threat_score(
    client,
    admin_headers,
):
    indicator_id = create_test_indicator()

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        reasons = (
            response.json()["explanation"]
            ["threat_score"]["reasons"]
        )

        assert (
            "HIGH severity contributes 85/100."
            in reasons
        )

    finally:
        delete_test_indicator()


def test_investigation_explains_persisted_reputation_score(
    client,
    admin_headers,
):
    indicator_id = create_test_indicator(
        reputation_score=40,
    )

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        explanation = response.json()["explanation"]

        assert explanation["reputation_score"]["value"] == 40

        assert (
            "Persisted reputation evidence score recorded "
            "during threat intelligence enrichment."
            in explanation["reputation_score"]["reasons"]
        )

    finally:
        delete_test_indicator()


def test_investigation_returns_confidence_explanation(
    client,
    admin_headers,
):
    indicator_id = create_test_indicator(
        threat_score=85,
        reputation_score=40,
        confidence_score=67,
    )

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        explanation = response.json()["explanation"]

        assert explanation["confidence_score"]["value"] == 67

        reasons = explanation["confidence_score"]["reasons"]

        assert (
            "60% threat score contribution: 51."
            in reasons
        )

        assert (
            "40% reputation evidence contribution: 16."
            in reasons
        )

        assert (
            "Persisted confidence score: 67/100."
            in reasons
        )

    finally:
        delete_test_indicator()


def test_investigation_returns_tag_reasons(
    client,
    admin_headers,
):
    indicator_id = create_test_indicator()

    try:
        response = client.get(
            f"/investigations/{indicator_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        tag_reasons = (
            response.json()["explanation"]
            ["tag_reasons"]
        )

        assert tag_reasons["ip"] == (
            "Indicator type is IP."
        )

        assert tag_reasons["high"] == (
            "Indicator severity is HIGH."
        )

        assert tag_reasons["high-risk"] == (
            "Indicator severity is HIGH or CRITICAL."
        )

    finally:
        delete_test_indicator()
