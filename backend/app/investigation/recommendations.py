from app.investigation.schemas import Recommendation


def generate_recommendation(
    threat_score: int,
    confidence_score: int,
    severity: str,
) -> Recommendation:

    severity = severity.upper()

    if severity == "CRITICAL":
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
        summary="No immediate action required.",
        priority="P3",
        actions=[
            "Continue monitoring",
        ],
    )