from sqlalchemy.orm import Session

from app.models.user import User
from app.schemas.alert import AlertCreate

from app.services.alert_service import (
    create_alert,
    get_alert_by_title,
)

from app.threat_intel.providers.manager import (
    ThreatProviderManager,
)

from app.threat_intel.models import Indicator
from app.threat_intel.schemas import IndicatorCreate


# -------------------------------------------------
# Threat Intelligence Provider Manager
# -------------------------------------------------

provider_manager = ThreatProviderManager()


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
        .filter(Indicator.value == value)
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


    # Duplicate alert protection
    if get_alert_by_title(db, title):
        return None


    admin = (
        db.query(User)
        .filter(User.role == "admin")
        .first()
    )


    alert_data = AlertCreate(
        title=title,
        description=indicator.description,
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

def ingest_threat_intelligence(
    db: Session,
) -> int:
    """
    Collect indicators from registered providers.

    Generates alerts automatically for
    HIGH and CRITICAL indicators.
    """

    added = 0


    indicators = (
        provider_manager.collect_indicators()
    )


    for item in indicators:

        if indicator_exists(
            db,
            item["value"],
        ):
            continue


        db_indicator = Indicator(
            **item
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
    """

    db_indicator = Indicator(
        **indicator.model_dump()
    )


    db.add(db_indicator)

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