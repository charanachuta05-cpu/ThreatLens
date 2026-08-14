import pytest

from app.investigation.recommendations import (
    generate_recommendation,
)
from app.investigation.schemas import (
    RecommendationPriority,
)


def test_threat_score_69_is_p3():
    recommendation = generate_recommendation(
        threat_score=69,
        confidence_score=100,
        severity="HIGH",
    )

    assert recommendation.priority == RecommendationPriority.P3


def test_threat_score_70_confidence_49_is_p3():
    recommendation = generate_recommendation(
        threat_score=70,
        confidence_score=49,
        severity="HIGH",
    )

    assert recommendation.priority == RecommendationPriority.P3


def test_threat_score_70_confidence_50_is_p2():
    recommendation = generate_recommendation(
        threat_score=70,
        confidence_score=50,
        severity="HIGH",
    )

    assert recommendation.priority == RecommendationPriority.P2


def test_maximum_scores_produce_p2():
    recommendation = generate_recommendation(
        threat_score=100,
        confidence_score=100,
        severity="HIGH",
    )

    assert recommendation.priority == RecommendationPriority.P2


def test_critical_overrides_maximum_or_minimum_scores():
    recommendation = generate_recommendation(
        threat_score=0,
        confidence_score=0,
        severity="critical",
    )

    assert recommendation.priority == RecommendationPriority.P1


def test_critical_severity_is_whitespace_tolerant():
    recommendation = generate_recommendation(
        threat_score=0,
        confidence_score=0,
        severity="  critical  ",
    )

    assert recommendation.priority == RecommendationPriority.P1


def test_high_threat_with_low_confidence_requires_validation():
    recommendation = generate_recommendation(
        threat_score=100,
        confidence_score=0,
        severity="HIGH",
    )

    assert recommendation.priority == RecommendationPriority.P3

    assert (
        recommendation.summary
        == (
            "High threat score with limited confidence; "
            "validate intelligence before escalation."
        )
    )

    assert (
        "Validate the intelligence source"
        in recommendation.actions
    )


@pytest.mark.parametrize(
    "threat_score,confidence_score",
    [
        (-1, 50),
        (101, 50),
        (50, -1),
        (50, 101),
    ],
)
def test_invalid_scores_are_rejected(
    threat_score,
    confidence_score,
):
    with pytest.raises(
        ValueError,
        match="must be between 0 and 100",
    ):
        generate_recommendation(
            threat_score=threat_score,
            confidence_score=confidence_score,
            severity="HIGH",
        )


def test_low_threat_produces_p3():
    recommendation = generate_recommendation(
        threat_score=0,
        confidence_score=100,
        severity="MEDIUM",
    )

    assert recommendation.priority == RecommendationPriority.P3

    assert (
        recommendation.summary
        == "No immediate action required."
    )

    assert recommendation.actions == [
        "Continue monitoring",
    ]