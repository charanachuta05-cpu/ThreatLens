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
    Compare two indicators and calculate a
    deterministic correlation score from 0 to 100.

    Scoring:

        Same type              +20
        Same severity          +20
        Same intelligence
        source                 +15
        Similar reputation     +15
        Similar confidence    +10
        Shared tags            +20

    Indicators are considered related when
    the final score is at least 60.
    """

    score = 0
    reasons: list[str] = []

    if left.type == right.type:
        score += 20
        reasons.append(
            "Same indicator type",
        )

    if left.severity == right.severity:
        score += 20
        reasons.append(
            "Same severity",
        )

    if left.source == right.source:
        score += 15
        reasons.append(
            "Same intelligence source",
        )

    reputation_difference = abs(
        left.reputation - right.reputation,
    )

    if reputation_difference <= 20:
        score += 15
        reasons.append(
            "Similar reputation",
        )

    confidence_difference = abs(
        left.confidence - right.confidence,
    )

    if confidence_difference <= 20:
        score += 10
        reasons.append(
            "Similar confidence",
        )

    shared_tags = (
        set(left.tags)
        & set(right.tags)
    )

    if shared_tags:
        score += 20
        reasons.append(
            "Shared tags: "
            + ", ".join(
                sorted(shared_tags),
            ),
        )

    score = min(
        score,
        100,
    )

    return CorrelationResult(
        score=score,
        related=score >= 60,
        reasons=reasons,
    )