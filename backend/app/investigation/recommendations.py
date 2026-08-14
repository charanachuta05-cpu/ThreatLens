from app.investigation.schemas import Recommendation


def generate_recommendation(
    threat_score: int,
    confidence_score: int,
    severity: str,
) -> Recommendation:
    """
    Generate an investigation recommendation from persisted
    threat intelligence scores.

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

    normalized_severity = severity.strip().upper()

    if normalized_severity == "CRITICAL":
        return Recommendation(
            summary="Immediate investigation and containment required.",
            priority="P1",
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
                priority="P2",
                actions=[
                    "Review recent activity",
                    "Check endpoint logs",
                    "Monitor network traffic",
                ],
            )

        return Recommendation(
            summary="High threat score with limited confidence; validate intelligence before escalation.",
            priority="P3",
            actions=[
                "Validate the intelligence source",
                "Review recent activity",
                "Check endpoint logs",
                "Monitor network traffic",
            ],
        )

    return Recommendation(
        summary="No immediate action required.",
        priority="P3",
        actions=[
            "Continue monitoring",
        ],
    )