from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.correlation.schemas import (
    CorrelatedIndicator,
    CorrelationAlert,
    CorrelationIndicator,
    CorrelationResponse,
    CorrelationSummary,
)
from app.models.alert import Alert
from app.threat_intel.correlation import (
    correlate_indicators,
)
from app.threat_intel.models import Indicator
from app.threat_intel.schemas import ThreatIndicator


STRONG_CORRELATION_THRESHOLD = 80


def _parse_tags(
    tags: str | None,
) -> list[str]:
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
    Convert a persisted Indicator into the normalized
    ThreatIndicator representation used by the existing
    ThreatLens correlation algorithm.

    Correlation intentionally uses persisted enrichment
    values and does not trigger provider requests.
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


def correlate_indicator(
    db: Session,
    indicator_id: int,
) -> CorrelationResponse:
    """
    Generate a deterministic correlation report for a
    persisted ThreatLens indicator.
    """

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

    current_indicator = (
        _build_threat_indicator(
            indicator,
        )
    )

    other_indicators = (
        db.query(Indicator)
        .filter(
            Indicator.id != indicator.id,
        )
        .all()
    )

    related_indicators: list[
        CorrelatedIndicator
    ] = []

    for other in other_indicators:
        comparison = correlate_indicators(
            current_indicator,
            _build_threat_indicator(
                other,
            ),
        )

        if not comparison.related:
            continue

        related_indicators.append(
            CorrelatedIndicator(
                id=other.id,
                value=other.value,
                indicator_type=(
                    other.indicator_type
                ),
                severity=other.severity,
                source=other.source,
                threat_score=(
                    other.threat_score
                ),
                reputation_score=(
                    other.reputation_score
                ),
                confidence_score=(
                    other.confidence_score
                ),
                correlation_score=(
                    comparison.score
                ),
                reasons=(
                    comparison.reasons
                ),
            ),
        )

    related_indicators.sort(
        key=lambda item: (
            -item.correlation_score,
            item.id,
        ),
    )

    related_indicator_ids = [
        item.id
        for item in related_indicators
    ]

    relevant_indicator_ids = [
        indicator.id,
        *related_indicator_ids,
    ]

    alerts = (
        db.query(Alert)
        .filter(
            or_(
                Alert.indicator_id.in_(
                    relevant_indicator_ids,
                ),
                (
                    Alert.indicator_id.is_(
                        None,
                    )
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

    highest_correlation_score = (
        related_indicators[
            0
        ].correlation_score
        if related_indicators
        else 0
    )

    strong_correlations = sum(
        1
        for item in related_indicators
        if item.correlation_score
        >= STRONG_CORRELATION_THRESHOLD
    )

    return CorrelationResponse(
        indicator=CorrelationIndicator(
            id=indicator.id,
            value=indicator.value,
            indicator_type=(
                indicator.indicator_type
            ),
            severity=indicator.severity,
            source=indicator.source,
            threat_score=(
                indicator.threat_score
            ),
            reputation_score=(
                indicator.reputation_score
            ),
            confidence_score=(
                indicator.confidence_score
            ),
            tags=_parse_tags(
                indicator.tags,
            ),
        ),
        summary=CorrelationSummary(
            total_indicators_compared=len(
                other_indicators,
            ),
            related_indicators=len(
                related_indicators,
            ),
            strong_correlations=(
                strong_correlations
            ),
            related_alerts=len(alerts),
            highest_correlation_score=(
                highest_correlation_score
            ),
        ),
        related_indicators=(
            related_indicators
        ),
        alerts=[
            CorrelationAlert(
                id=alert.id,
                title=alert.title,
                severity=(
                    alert.severity.value
                    if hasattr(
                        alert.severity,
                        "value",
                    )
                    else str(
                        alert.severity
                    )
                ),
                status=(
                    alert.status.value
                    if hasattr(
                        alert.status,
                        "value",
                    )
                    else str(
                        alert.status
                    )
                ),
                indicator_id=(
                    alert.indicator_id
                ),
            )
            for alert in alerts
        ],
    )
