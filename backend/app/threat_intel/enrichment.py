from dataclasses import dataclass

from app.threat_intel.scoring import calculate_threat_score
from app.threat_intel.reputation import calculate_reputation
from app.threat_intel.schemas import ThreatIndicator


@dataclass(slots=True)
class EnrichedIndicator:
    """
    Result of IOC enrichment.

    Future versions will include:

    confidence_score
    tags
    provider metadata
    """

    threat_score: int

    reputation_score: int


def enrich_indicator(
    indicator: ThreatIndicator,
) -> EnrichedIndicator:
    """
    Run the IOC enrichment pipeline.
    """

    return EnrichedIndicator(
        threat_score=calculate_threat_score(
            indicator.severity
        ),
        reputation_score=calculate_reputation(
            indicator
        ),
    )