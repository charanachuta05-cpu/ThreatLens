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
        tags=[],
    )


def investigate_indicator(
    db: Session,
    indicator_id: int,
) -> InvestigationResponse:
    """
    Generate a complete investigation report.
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

    confidence_score = round(
        indicator.threat_score * 0.6
        + indicator.reputation_score * 0.4
    )

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
        key=lambda x: x["correlation_score"],
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
        tags=[],
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