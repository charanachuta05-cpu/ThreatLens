from app.investigation.schemas import (
    Recommendation,
    RecommendationPriority,
)


def _validate_score(
    value: int,
    field_name: str,
) -> None:
    if not 0 <= value <= 100:
        raise ValueError(
            f"{field_name} must be between 0 and 100."
        )


def generate_recommendation(
    threat_score: int,
    confidence_score: int,
    severity: str,
) -> Recommendation:
    """
    Generate an investigation recommendation from
    persisted threat intelligence scores.

    Priority policy:

    CRITICAL severity:
        Always P1.

    High threat score with sufficient confidence:
        P2.

    High threat score with low confidence:
        P3 because the result requires validation.

    Everything else:
        P3.
    """

    _validate_score(
        threat_score,
        "threat_score",
    )
    _validate_score(
        confidence_score,
        "confidence_score",
    )

    normalized_severity = severity.strip().upper()

    if normalized_severity == "CRITICAL":
        return Recommendation(
            summary=(
                "Immediate investigation and containment required."
            ),
            priority=RecommendationPriority.P1,
            actions=[
                "Block the indicator",
                "Review related alerts",
                "Isolate affected systems",
                "Collect forensic evidence",
                "Notify Incident Response",
            ],
        )

    if threat_score >= 70:
        if confidence_score >= 50:
            return Recommendation(
                summary="Monitor and validate.",
                priority=RecommendationPriority.P2,
                actions=[
                    "Review recent activity",
                    "Check endpoint logs",
                    "Monitor network traffic",
                ],
            )

        return Recommendation(
            summary=(
                "High threat score with limited confidence; "
                "validate intelligence before escalation."
            ),
            priority=RecommendationPriority.P3,
            actions=[
                "Validate the intelligence source",
                "Review recent activity",
                "Check endpoint logs",
                "Monitor network traffic",
            ],
        )

    return Recommendation(
        summary="No immediate action required.",
        priority=RecommendationPriority.P3,
        actions=[
            "Continue monitoring",
        ],
    )