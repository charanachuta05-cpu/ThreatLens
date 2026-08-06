from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.alert import AlertCreate

from app.services.alert_service import (
    create_alert,
    get_alert_by_title,
)

from app.threat_intel.providers.factory import get_providers
from app.threat_intel.providers.manager import ThreatProviderManager

from app.threat_intel.models import Indicator
from app.threat_intel.schemas import IndicatorCreate

from app.threat_intel.enrichment import enrich_indicator


# -------------------------------------------------
# Threat Intelligence Provider Manager
# -------------------------------------------------

provider_manager = ThreatProviderManager(
    get_providers()
)


# -------------------------------------------------
# Indicator Utilities
# -------------------------------------------------

def indicator_exists(
    db: Session,
    value: str,
) -> Indicator | None:
    """
    Check whether an indicator already exists.
    """

    return (
        db.query(Indicator)
        .filter(
            Indicator.value == value
        )
        .first()
    )


# -------------------------------------------------
# Automatic Alert Generation
# -------------------------------------------------

def generate_alert_for_indicator(
    db: Session,
    indicator: Indicator,
):
    """
    Generate alerts for HIGH and CRITICAL indicators.

    Prevents duplicate alerts.
    """

    if indicator.severity not in (
        "HIGH",
        "CRITICAL",
    ):
        return None


    title = (
        f"Threat Indicator: {indicator.value}"
    )


    if get_alert_by_title(db, title):
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
            if indicator.description
            else (
                "Automatically generated alert "
                f"for malicious indicator {indicator.value}"
            )
        ),
        severity=indicator.severity,
        source=indicator.source,
    )


    return create_alert(
        db=db,
        alert_data=alert_data,
        created_by=admin.id if admin else None,
    )


# -------------------------------------------------
# Threat Intelligence Ingestion Engine
# -------------------------------------------------

async def ingest_threat_intelligence(
    db: Session,
) -> int:
    """
    Collect indicators from registered providers.

    Applies IOC enrichment before storage.

    Generates alerts automatically for
    HIGH and CRITICAL indicators.
    """

    added = 0


    indicators = await provider_manager.collect_all()


    for item in indicators:

        indicator_data = item.model_dump()


        if indicator_exists(
            db,
            indicator_data["value"],
        ):
            continue


        enriched = enrich_indicator(
            severity=indicator_data["severity"],
        )


        db_indicator = Indicator(
            indicator_type=indicator_data["type"],
            value=indicator_data["value"],
            severity=indicator_data["severity"],
            threat_score=enriched.threat_score,
            source=indicator_data["source"],
            description=indicator_data.get(
                "description"
            ),
        )


        db.add(db_indicator)

        db.flush()


        generate_alert_for_indicator(
            db,
            db_indicator,
        )


        added += 1


    db.commit()


    return added


# -------------------------------------------------
# Manual Indicator Creation API
# -------------------------------------------------

def create_indicator(
    db: Session,
    indicator: IndicatorCreate,
) -> Indicator:
    """
    Create indicator manually.

    Applies IOC enrichment before storage.

    Generates alerts automatically for
    HIGH and CRITICAL indicators.
    """

    data = indicator.model_dump()


    enriched = enrich_indicator(
        severity=data["severity"],
    )


    db_indicator = Indicator(
        **data,
        threat_score=enriched.threat_score,
    )


    db.add(db_indicator)

    db.flush()


    generate_alert_for_indicator(
        db,
        db_indicator,
    )


    db.commit()

    db.refresh(
        db_indicator
    )


    return db_indicator


# -------------------------------------------------
# Retrieve Indicators
# -------------------------------------------------

def get_indicators(
    db: Session,
):
    """
    Return all stored indicators.
    """

    return (
        db.query(Indicator)
        .all()
    )