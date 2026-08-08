from sqlalchemy.orm import Session

from app.threat_intel.models import Indicator


def hunt_high_risk(
    db: Session,
):
    """
    Return indicators with a high threat score.
    """

    return (
        db.query(Indicator)
        .filter(
            Indicator.threat_score >= 80
        )
        .order_by(
            Indicator.threat_score.desc(),
            Indicator.created_at.desc(),
        )
        .all()
    )


def hunt_recent(
    db: Session,
    limit: int = 20,
):
    """
    Return recently ingested indicators.
    """

    return (
        db.query(Indicator)
        .order_by(
            Indicator.created_at.desc()
        )
        .limit(limit)
        .all()
    )


def hunt_by_source(
    db: Session,
    source: str,
):
    """
    Hunt indicators by intelligence source.
    """

    return (
        db.query(Indicator)
        .filter(
            Indicator.source.ilike(
                f"%{source}%"
            )
        )
        .all()
    )