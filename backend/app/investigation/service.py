from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.threat_intel.models import Indicator
from app.threat_intel.schemas import ThreatIndicator
from app.threat_intel.correlation import correlate_indicators

from app.investigation.recommendations import (
    generate_recommendation,
)
from app.investigation.schemas import (
    InvestigationResponse,
    InvestigationScores,
)


def _build_threat_indicator(
    indicator: Indicator,
) -> ThreatIndicator:
    """
    Convert a database Indicator into the
    normalized ThreatIndicator schema.
    """

    return ThreatIndicator(
        value=indicator.value,
        type=indicator.indicator_type,
        source=indicator.source,
        severity=indicator.severity,
        reputation=indicator.reputation_score,
        malicious=0,
        suspicious=0,
        harmless=0,
        tags=_parse_tags(indicator.tags),
    )


def _parse_tags(
    tags: str | None,
) -> list[str]:
    """
    Convert database CSV tags into a clean,
    deterministic list.

    Example:
        "ip,high,high-risk"

    becomes:
        ["ip", "high", "high-risk"]
    """

    if not tags:
        return []

    parsed_tags = []
    seen = set()

    for tag in tags.split(","):
        cleaned_tag = tag.strip()

        if not cleaned_tag:
            continue

        if cleaned_tag in seen:
            continue

        seen.add(cleaned_tag)
        parsed_tags.append(cleaned_tag)

    return parsed_tags


def investigate_indicator(
    db: Session,
    indicator_id: int,
) -> InvestigationResponse:
    """
    Generate a complete investigation report
    using persisted enrichment results.
    """

    indicator = (
        db.query(Indicator)
        .filter(
            Indicator.id == indicator_id
        )
        .first()
    )

    if indicator is None:
        raise ValueError(
            "Indicator not found."
        )

    current_indicator = _build_threat_indicator(
        indicator
    )

    alerts = (
        db.query(Alert)
        .filter(
            Alert.title.contains(
                indicator.value
            )
        )
        .all()
    )

    # IMPORTANT:
    # Use the confidence score persisted by the
    # enrichment pipeline. Do not recalculate it.
    confidence_score = indicator.confidence_score

    recommendation = generate_recommendation(
        indicator.threat_score,
        confidence_score,
        indicator.severity,
    )

    related_indicators = []

    all_indicators = (
        db.query(Indicator)
        .filter(
            Indicator.id != indicator.id
        )
        .all()
    )

    for other in all_indicators:
        comparison = correlate_indicators(
            current_indicator,
            _build_threat_indicator(other),
        )

        if comparison.related:
            related_indicators.append(
                {
                    "id": other.id,
                    "value": other.value,
                    "indicator_type": other.indicator_type,
                    "severity": other.severity,
                    "source": other.source,
                    "correlation_score": comparison.score,
                    "reasons": comparison.reasons,
                }
            )

    related_indicators.sort(
        key=lambda item: item["correlation_score"],
        reverse=True,
    )

    return InvestigationResponse(
        indicator={
            "id": indicator.id,
            "value": indicator.value,
            "type": indicator.indicator_type,
            "severity": indicator.severity,
            "source": indicator.source,
        },
        scores=InvestigationScores(
            threat_score=indicator.threat_score,
            reputation_score=indicator.reputation_score,
            confidence_score=confidence_score,
        ),
        tags=_parse_tags(
            indicator.tags
        ),
        related_indicators=related_indicators,
        alerts=[
            {
                "id": alert.id,
                "title": alert.title,
            }
            for alert in alerts
        ],
        recommendation=recommendation,
    )