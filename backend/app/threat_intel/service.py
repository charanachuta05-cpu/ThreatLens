from fastapi import HTTPException
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.logging.audit import audit_event
from app.models.user import User
from app.schemas.alert import AlertCreate
from app.services.alert_service import (
    create_alert,
    get_alert_by_title,
)
from app.threat_intel.enrichment import enrich_indicator
from app.threat_intel.models import Indicator
from app.threat_intel.providers.factory import get_providers
from app.threat_intel.providers.manager import ThreatProviderManager
from app.threat_intel.schemas import (
    IndicatorCreate,
    ThreatIndicator,
)


provider_manager = ThreatProviderManager(
    get_providers()
)


def indicator_exists(
    db: Session,
    value: str,
) -> Indicator | None:
    return (
        db.query(Indicator)
        .filter(
            Indicator.value == value
        )
        .first()
    )


def generate_alert_for_indicator(
    db: Session,
    indicator: Indicator,
):
    """
    Automatically generate alerts for
    HIGH and CRITICAL indicators.
    """

    if indicator.severity not in {
        "HIGH",
        "CRITICAL",
    }:
        return None

    title = (
        f"Threat Indicator: {indicator.value}"
    )

    if get_alert_by_title(
        db,
        title,
    ):
        return None

    admin = (
        db.query(User)
        .filter(
            User.role == "admin"
        )
        .first()
    )

    alert_data = AlertCreate(
        title=title,
        description=(
            indicator.description
            or (
                "Automatically generated alert "
                f"for malicious indicator "
                f"{indicator.value}"
            )
        ),
        severity=indicator.severity,
        source=indicator.source,
    )

    return create_alert(
        db=db,
        alert_data=alert_data,
        created_by=(
            admin.id
            if admin
            else None
        ),
    )


async def ingest_threat_intelligence(
    db: Session,
) -> int:
    """
    Collect, enrich and persist indicators
    from registered threat intelligence providers.
    """

    added = 0

    indicators = (
        await provider_manager.collect_all()
    )

    try:
        for item in indicators:

            value = item.value.strip()

            if indicator_exists(
                db,
                value,
            ):
                continue

            enriched = enrich_indicator(
                item
            )

            db_indicator = Indicator(
                indicator_type=item.type.upper(),
                value=value,
                severity=item.severity.upper(),
                threat_score=enriched.threat_score,
                reputation_score=enriched.reputation_score,
                confidence_score=enriched.confidence_score,
                source=item.source.strip(),
                description=None,
                tags=",".join(
                    enriched.tags
                ),
            )

            db.add(db_indicator)
            db.flush()

            generate_alert_for_indicator(
                db,
                db_indicator,
            )

            audit_event(
                action="AUTO_INGEST_INDICATOR",
                actor="scheduler",
                target=db_indicator.value,
            )

            added += 1

        db.commit()

        return added

    except SQLAlchemyError:
        db.rollback()
        raise


def create_indicator(
    db: Session,
    indicator: IndicatorCreate,
) -> Indicator:
    """
    Create, enrich and persist an indicator.
    """

    normalized_value = (
        indicator.value.strip()
    )

    existing = indicator_exists(
        db,
        normalized_value,
    )

    if existing:
        raise HTTPException(
            status_code=409,
            detail=(
                f"Indicator "
                f"'{normalized_value}' "
                "already exists."
            ),
        )

    normalized = ThreatIndicator(
        value=normalized_value,
        type=indicator.indicator_type.value,
        source=indicator.source.strip(),
        severity=indicator.severity.value,
    )

    enriched = enrich_indicator(
        normalized
    )

    db_indicator = Indicator(
        indicator_type=(
            indicator.indicator_type.value
        ),
        value=normalized_value,
        severity=indicator.severity.value,
        threat_score=enriched.threat_score,
        reputation_score=enriched.reputation_score,
        confidence_score=enriched.confidence_score,
        source=indicator.source.strip(),
        description=indicator.description,
        tags=",".join(
            enriched.tags
        ),
    )

    try:
        db.add(db_indicator)
        db.flush()

        generate_alert_for_indicator(
            db,
            db_indicator,
        )

        db.commit()
        db.refresh(db_indicator)

        audit_event(
            action="CREATE_INDICATOR",
            actor="system",
            target=db_indicator.value,
        )

        return db_indicator

    except SQLAlchemyError:
        db.rollback()
        raise


def get_indicators(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    search: str | None = None,
    severity: str | None = None,
    source: str | None = None,
    min_score: int | None = None,
    sort_by: str = "created_at",
    order: str = "desc",
):
    """
    Retrieve indicators with filtering,
    pagination and safe sorting.
    """

    allowed_sort_fields = {
        "created_at": Indicator.created_at,
        "threat_score": Indicator.threat_score,
        "reputation_score": Indicator.reputation_score,
        "confidence_score": Indicator.confidence_score,
        "severity": Indicator.severity,
        "source": Indicator.source,
    }

    sort_column = allowed_sort_fields.get(
        sort_by
    )

    if sort_column is None:
        raise HTTPException(
            status_code=400,
            detail=(
                f"Unsupported sort field: "
                f"{sort_by}"
            ),
        )

    query = db.query(Indicator)

    if search:
        query = query.filter(
            Indicator.value.ilike(
                f"%{search.strip()}%"
            )
        )

    if severity:
        query = query.filter(
            Indicator.severity
            == severity.strip().upper()
        )

    if source:
        query = query.filter(
            Indicator.source.ilike(
                f"%{source.strip()}%"
            )
        )

    if min_score is not None:
        query = query.filter(
            Indicator.threat_score
            >= min_score
        )

    normalized_order = (
        order.strip().lower()
    )

    if normalized_order == "desc":
        query = query.order_by(
            sort_column.desc()
        )

    elif normalized_order == "asc":
        query = query.order_by(
            sort_column.asc()
        )

    else:
        raise HTTPException(
            status_code=400,
            detail=(
                "Order must be 'asc' or 'desc'."
            ),
        )

    return (
        query
        .offset(skip)
        .limit(limit)
        .all()
    )