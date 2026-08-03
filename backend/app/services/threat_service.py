from sqlalchemy.orm import Session

from app.models.threat import ThreatIndicator
from app.schemas.threat import (
    ThreatIndicatorCreate,
    ThreatIndicatorUpdate,
)


def create_threat_indicator(
    db: Session,
    threat_data: ThreatIndicatorCreate,
):
    threat = ThreatIndicator(
        indicator_type=threat_data.indicator_type,
        value=threat_data.value,
        severity=threat_data.severity,
        source=threat_data.source,
        description=threat_data.description,
    )

    db.add(threat)
    db.commit()
    db.refresh(threat)

    return threat


def get_threat_indicators(
    db: Session,
    skip: int = 0,
    limit: int = 20,
    search: str | None = None,
    severity: str | None = None,
    indicator_type: str | None = None,
    source: str | None = None,
):
    query = db.query(ThreatIndicator)

    if search:
        query = query.filter(
            ThreatIndicator.value.ilike(f"%{search}%")
        )

    if severity:
        query = query.filter(
            ThreatIndicator.severity == severity
        )

    if indicator_type:
        query = query.filter(
            ThreatIndicator.indicator_type == indicator_type
        )

    if source:
        query = query.filter(
            ThreatIndicator.source.ilike(f"%{source}%")
        )

    return (
        query
        .order_by(ThreatIndicator.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )


def get_threat_by_id(
    db: Session,
    threat_id: int,
):
    return (
        db.query(ThreatIndicator)
        .filter(
            ThreatIndicator.id == threat_id
        )
        .first()
    )


def update_threat_indicator(
    db: Session,
    threat: ThreatIndicator,
    threat_data: ThreatIndicatorUpdate,
):
    update_data = threat_data.model_dump(
        exclude_unset=True
    )

    for key, value in update_data.items():
        setattr(
            threat,
            key,
            value
        )

    db.commit()
    db.refresh(threat)

    return threat


def delete_threat_indicator(
    db: Session,
    threat: ThreatIndicator,
):
    db.delete(threat)
    db.commit()