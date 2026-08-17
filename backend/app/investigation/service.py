from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.investigation.recommendations import (
    generate_recommendation,
)
from app.investigation.schemas import (
    InvestigationAlert,
    InvestigationIndicator,
    InvestigationResponse,
    InvestigationScores,
    RelatedIndicator,
)
from app.models.alert import Alert
from app.threat_intel.correlation import correlate_indicators
from app.threat_intel.explanation import (
    explain_enrichment,
)
from app.threat_intel.models import Indicator
from app.threat_intel.schemas import ThreatIndicator


def _parse_tags(
    tags: str | None,
) -> list[str]:
    """
    Convert database CSV tags into a clean,
    deterministic list.
    """

    if not tags:
        return []

    parsed_tags: list[str] = []
    seen: set[str] = set()

    for tag in tags.split(","):
        cleaned_tag = tag.strip()

        if not cleaned_tag:
            continue

        if cleaned_tag in seen:
            continue

        seen.add(cleaned_tag)
        parsed_tags.append(cleaned_tag)

    return parsed_tags


def _build_threat_indicator(
    indicator: Indicator,
) -> ThreatIndicator:
    """
    Convert a database Indicator into the normalized
    ThreatIndicator schema used by the correlation engine.

    Persisted enrichment values are used so that investigation
    results remain deterministic and do not trigger provider calls.
    """

    return ThreatIndicator(
        value=indicator.value,
        type=indicator.indicator_type,
        source=indicator.source,
        severity=indicator.severity,
        reputation=indicator.reputation_score,
        confidence=indicator.confidence_score,
        malicious=0,
        suspicious=0,
        harmless=0,
        tags=_parse_tags(
            indicator.tags,
        ),
    )


def investigate_indicator(
    db: Session,
    indicator_id: int,
) -> InvestigationResponse:
    """
    Generate a complete investigation report using
    persisted enrichment results.

    Alert relationships are resolved primarily through
    Alert.indicator_id. The title/description fallback
    preserves compatibility with historical alerts that
    were created before the indicator relationship existed.
    """

    # --------------------------------------------------------
    # Retrieve indicator
    # --------------------------------------------------------

    indicator = (
        db.query(Indicator)
        .filter(
            Indicator.id == indicator_id,
        )
        .first()
    )

    if indicator is None:
        raise ValueError(
            "Indicator not found.",
        )

    # --------------------------------------------------------
    # Normalize indicator for correlation and explanation
    # --------------------------------------------------------

    current_indicator = _build_threat_indicator(
        indicator,
    )

    # --------------------------------------------------------
    # Retrieve alerts associated with this indicator
    # --------------------------------------------------------

    alerts = (
        db.query(Alert)
        .filter(
            or_(
                Alert.indicator_id == indicator.id,
                (
                    Alert.indicator_id.is_(None)
                    & (
                        Alert.title.contains(
                            indicator.value,
                        )
                        | Alert.description.contains(
                            indicator.value,
                        )
                    )
                ),
            ),
        )
        .order_by(
            Alert.created_at.desc(),
            Alert.id.desc(),
        )
        .all()
    )

    # --------------------------------------------------------
    # Use persisted confidence score
    #
    # Do not recalculate confidence during investigation.
    # This keeps investigation results deterministic.
    # --------------------------------------------------------

    confidence_score = indicator.confidence_score

    # --------------------------------------------------------
    # Generate deterministic enrichment explanation
    #
    # The persisted confidence score remains authoritative.
    # --------------------------------------------------------

    explanation = explain_enrichment(
        current_indicator,
        persisted_reputation_score=indicator.reputation_score,
        persisted_confidence_score=confidence_score,
    )

    # --------------------------------------------------------
    # Generate recommendation
    # --------------------------------------------------------

    recommendation = generate_recommendation(
        indicator.threat_score,
        confidence_score,
        indicator.severity,
    )

    # --------------------------------------------------------
    # Correlate related indicators
    # --------------------------------------------------------

    related_indicators: list[RelatedIndicator] = []

    all_indicators = (
        db.query(Indicator)
        .filter(
            Indicator.id != indicator.id,
        )
        .all()
    )

    for other in all_indicators:
        comparison = correlate_indicators(
            current_indicator,
            _build_threat_indicator(other),
        )

        if not comparison.related:
            continue

        related_indicators.append(
            RelatedIndicator(
                id=other.id,
                value=other.value,
                indicator_type=other.indicator_type,
                severity=other.severity,
                source=other.source,
                correlation_score=comparison.score,
                reasons=comparison.reasons,
            ),
        )

    # --------------------------------------------------------
    # Highest correlation first.
    #
    # ID provides deterministic ordering when scores tie.
    # --------------------------------------------------------

    related_indicators.sort(
        key=lambda item: (
            -item.correlation_score,
            item.id,
        ),
    )

    # --------------------------------------------------------
    # Build investigation response
    # --------------------------------------------------------

    return InvestigationResponse(
        indicator=InvestigationIndicator(
            id=indicator.id,
            value=indicator.value,
            type=indicator.indicator_type,
            severity=indicator.severity,
            source=indicator.source,
        ),
        scores=InvestigationScores(
            threat_score=indicator.threat_score,
            reputation_score=indicator.reputation_score,
            confidence_score=confidence_score,
        ),
        explanation=explanation,
        tags=_parse_tags(
            indicator.tags,
        ),
        related_indicators=related_indicators,
        alerts=[
            InvestigationAlert(
                id=alert.id,
                title=alert.title,
                indicator_id=alert.indicator_id,
            )
            for alert in alerts
        ],
        recommendation=recommendation,
    )