from app.investigation.recommendations import (
    generate_recommendation,
)


def test_critical_recommendation_is_p1():
    recommendation = generate_recommendation(
        threat_score=50,
        confidence_score=80,
        severity="CRITICAL",
    )

    assert recommendation.priority == "P1"

    assert (
        recommendation.summary
        == "Immediate investigation and containment required."
    )

    assert "Block the indicator" in recommendation.actions
    assert "Review related alerts" in recommendation.actions


def test_high_threat_recommendation_is_p2():
    recommendation = generate_recommendation(
        threat_score=70,
        confidence_score=80,
        severity="HIGH",
    )

    assert recommendation.priority == "P2"

    assert (
        recommendation.summary
        == "Monitor and validate."
    )

    assert "Review recent activity" in recommendation.actions


def test_low_threat_recommendation_is_p3():
    recommendation = generate_recommendation(
        threat_score=69,
        confidence_score=80,
        severity="MEDIUM",
    )

    assert recommendation.priority == "P3"

    assert (
        recommendation.summary
        == "No immediate action required."
    )

    assert recommendation.actions == [
        "Continue monitoring",
    ]


def test_critical_severity_overrides_threat_score():
    recommendation = generate_recommendation(
        threat_score=10,
        confidence_score=20,
        severity="critical",
    )

    assert recommendation.priority == "P1"

def test_high_threat_with_low_confidence_requires_validation():
    recommendation = generate_recommendation(
        threat_score=90,
        confidence_score=20,
        severity="HIGH",
    )

    assert recommendation.priority == "P3"
    assert (
        recommendation.summary
        == "High threat score with limited confidence; "
        "validate intelligence before escalation."
    )
    assert "Validate the intelligence source" in recommendation.actions

def test_high_threat_with_50_confidence_is_p2():
    recommendation = generate_recommendation(
        threat_score=70,
        confidence_score=50,
        severity="HIGH",
    )

    assert recommendation.priority == "P2"