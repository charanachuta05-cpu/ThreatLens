from dataclasses import dataclass

from app.threat_intel.schemas import ThreatIndicator


@dataclass(slots=True)
class CorrelationResult:
    """
    Result of comparing two threat indicators.
    """

    score: int
    related: bool
    reasons: list[str]


def correlate_indicators(
    left: ThreatIndicator,
    right: ThreatIndicator,
) -> CorrelationResult:
    """
    Compare two indicators and calculate
    a correlation score from 0 to 100.
    """

    score = 0
    reasons: list[str] = []

    if left.type == right.type:
        score += 20
        reasons.append("Same indicator type")

    if left.severity == right.severity:
        score += 20
        reasons.append("Same severity")

    if left.source == right.source:
        score += 20
        reasons.append("Same intelligence source")

    reputation_difference = abs(
        left.reputation - right.reputation
    )

    if reputation_difference <= 20:
        score += 20
        reasons.append("Similar reputation")

    shared_tags = (
        set(left.tags)
        & set(right.tags)
    )

    if shared_tags:
        score += 20
        reasons.append(
            "Shared tags: "
            + ", ".join(sorted(shared_tags))
        )

    score = min(score, 100)

    return CorrelationResult(
        score=score,
        related=score >= 60,
        reasons=reasons,
    )