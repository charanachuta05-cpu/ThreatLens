from dataclasses import dataclass

from app.threat_intel.scoring import calculate_threat_score


@dataclass(slots=True)
class EnrichedIndicator:
    """
    Result returned by the enrichment pipeline.

    Additional fields (reputation, confidence, tags, etc.)
    will be added in future milestones.
    """

    threat_score: int


def enrich_indicator(
    *,
    severity: str,
) -> EnrichedIndicator:
    """
    Enrich an indicator before it is stored.

    Version 1:
        - Calculates the threat score.

    Future versions:
        - Reputation scoring
        - Confidence calculation
        - Threat tags
        - External provider enrichment
    """

    return EnrichedIndicator(
        threat_score=calculate_threat_score(
            severity
        )
    )