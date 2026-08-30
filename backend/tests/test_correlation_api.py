from app.core.database import SessionLocal
from app.core.security import create_access_token
from app.models.alert import Alert
from app.threat_intel.models import Indicator


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


def delete_indicator_by_value(
    value: str,
):
    """
    Delete a test indicator and alerts that directly
    reference it.
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
            db.query(Alert).filter(
                Alert.indicator_id
                == indicator.id,
            ).delete(
                synchronize_session=False,
            )

            db.delete(indicator)

        db.commit()

    finally:
        db.rollback()
        db.close()


def create_test_indicator(
    *,
    value: str,
    severity: str = "HIGH",
    source: str = "correlation-api-test",
    threat_score: int = 85,
    reputation_score: int = 80,
    confidence_score: int = 82,
    tags: str = "ip,high,high-risk,malicious",
) -> int:
    """
    Create a persisted indicator for correlation API tests.
    """

    delete_indicator_by_value(value)

    db = SessionLocal()

    try:
        indicator = Indicator(
            indicator_type="IP",
            value=value,
            severity=severity,
            source=source,
            description=(
                "Correlation API test indicator"
            ),
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


def test_admin_can_run_correlation(
    client,
    admin_headers,
):
    primary_value = "198.51.100.201"
    related_value = "198.51.100.202"

    primary_id = create_test_indicator(
        value=primary_value,
    )

    related_id = create_test_indicator(
        value=related_value,
    )

    try:
        response = client.get(
            f"/correlation/{primary_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        data = response.json()

        assert (
            data["indicator"]["id"]
            == primary_id
        )

        assert (
            data["indicator"]["value"]
            == primary_value
        )

        related_ids = {
            item["id"]
            for item in data[
                "related_indicators"
            ]
        }

        assert related_id in related_ids

        matching = next(
            item
            for item in data[
                "related_indicators"
            ]
            if item["id"] == related_id
        )

        assert (
            matching["correlation_score"]
            >= 60
        )

        assert matching["reasons"]

        assert (
            data["summary"][
                "related_indicators"
            ]
            >= 1
        )

    finally:
        delete_indicator_by_value(
            related_value,
        )
        delete_indicator_by_value(
            primary_value,
        )


def test_analyst_can_run_correlation(
    client,
):
    value = "198.51.100.211"

    indicator_id = create_test_indicator(
        value=value,
    )

    headers = make_role_headers(
        user_id=2,
        email="analyst@threatlens.com",
        role="analyst",
    )

    try:
        response = client.get(
            f"/correlation/{indicator_id}",
            headers=headers,
        )

        assert response.status_code == 200

        assert (
            response.json()[
                "indicator"
            ]["id"]
            == indicator_id
        )

    finally:
        delete_indicator_by_value(
            value,
        )


def test_viewer_cannot_run_correlation(
    client,
):
    value = "198.51.100.221"

    indicator_id = create_test_indicator(
        value=value,
    )

    headers = make_role_headers(
        user_id=3,
        email="viewer@threatlens.com",
        role="viewer",
    )

    try:
        response = client.get(
            f"/correlation/{indicator_id}",
            headers=headers,
        )

        assert response.status_code == 403

    finally:
        delete_indicator_by_value(
            value,
        )


def test_unauthenticated_user_cannot_run_correlation(
    client,
):
    value = "198.51.100.231"

    indicator_id = create_test_indicator(
        value=value,
    )

    try:
        response = client.get(
            f"/correlation/{indicator_id}",
        )

        assert response.status_code == 401

    finally:
        delete_indicator_by_value(
            value,
        )


def test_unknown_indicator_returns_404(
    client,
    admin_headers,
):
    response = client.get(
        "/correlation/999999999",
        headers=admin_headers,
    )

    assert response.status_code == 404

    data = response.json()

    assert data["success"] is False
    assert data["error"]["code"] == 404
    assert (
        data["error"]["message"]
        == "Indicator not found."
    )


def test_correlation_results_are_sorted_highest_first(
    client,
    admin_headers,
):
    primary_value = "198.51.100.241"
    strong_value = "198.51.100.242"
    weaker_value = "198.51.100.243"

    primary_id = create_test_indicator(
        value=primary_value,
        severity="CRITICAL",
        source="correlation-sort-test",
        reputation_score=90,
        confidence_score=90,
        tags=(
            "ip,critical,high-risk,"
            "malicious"
        ),
    )

    create_test_indicator(
        value=strong_value,
        severity="CRITICAL",
        source="correlation-sort-test",
        reputation_score=91,
        confidence_score=91,
        tags=(
            "ip,critical,high-risk,"
            "malicious"
        ),
    )

    create_test_indicator(
        value=weaker_value,
        severity="CRITICAL",
        source="different-source",
        reputation_score=91,
        confidence_score=91,
        tags="ip,critical",
    )

    try:
        response = client.get(
            f"/correlation/{primary_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        results = response.json()[
            "related_indicators"
        ]

        scores = [
            item["correlation_score"]
            for item in results
        ]

        assert scores == sorted(
            scores,
            reverse=True,
        )

    finally:
        delete_indicator_by_value(
            weaker_value,
        )
        delete_indicator_by_value(
            strong_value,
        )
        delete_indicator_by_value(
            primary_value,
        )


def test_correlation_summary_matches_results(
    client,
    admin_headers,
):
    primary_value = "198.51.100.251"

    primary_id = create_test_indicator(
        value=primary_value,
    )

    try:
        response = client.get(
            f"/correlation/{primary_id}",
            headers=admin_headers,
        )

        assert response.status_code == 200

        data = response.json()

        related = data[
            "related_indicators"
        ]

        summary = data["summary"]

        assert (
            summary["related_indicators"]
            == len(related)
        )

        expected_highest = (
            related[0][
                "correlation_score"
            ]
            if related
            else 0
        )

        assert (
            summary[
                "highest_correlation_score"
            ]
            == expected_highest
        )

        expected_strong = sum(
            1
            for item in related
            if item[
                "correlation_score"
            ]
            >= 80
        )

        assert (
            summary[
                "strong_correlations"
            ]
            == expected_strong
        )

    finally:
        delete_indicator_by_value(
            primary_value,
        )