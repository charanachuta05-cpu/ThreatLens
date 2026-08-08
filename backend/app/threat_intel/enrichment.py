from dataclasses import dataclass

from app.threat_intel.confidence import calculate_confidence
from app.threat_intel.reputation import calculate_reputation
from app.threat_intel.scoring import calculate_threat_score
from app.threat_intel.schemas import ThreatIndicator
from app.threat_intel.tags import generate_tags


@dataclass(slots=True)
class EnrichedIndicator:
    """
    Result produced by the IOC enrichment engine.
    """

    threat_score: int
    reputation_score: int
    confidence_score: int
    tags: list[str]


def enrich_indicator(
    indicator: ThreatIndicator,
) -> EnrichedIndicator:
    """
    Enrich a normalized threat indicator.
    """

    threat_score = calculate_threat_score(
        indicator.severity
    )

    reputation_score = calculate_reputation(
        indicator
    )

    confidence_score = calculate_confidence(
        threat_score,
        reputation_score,
    )

    tags = generate_tags(
        indicator
    )

    return EnrichedIndicator(
        threat_score=threat_score,
        reputation_score=reputation_score,
        confidence_score=confidence_score,
        tags=tags,
    )