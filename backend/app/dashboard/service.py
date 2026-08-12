from sqlalchemy import func
from sqlalchemy.orm import Session

from app.dashboard.schemas import DashboardSummary
from app.models.alert import Alert, AlertStatus
from app.threat_intel.models import Indicator


def get_dashboard_summary(
    db: Session,
) -> DashboardSummary:

    total = (
        db.query(Indicator)
        .count()
    )

    critical = (
        db.query(Indicator)
        .filter(
            Indicator.severity == "CRITICAL"
        )
        .count()
    )

    high = (
        db.query(Indicator)
        .filter(
            Indicator.severity == "HIGH"
        )
        .count()
    )

    active_alerts = (
        db.query(Alert)
        .filter(
            Alert.status.in_(
                [
                    AlertStatus.OPEN,
                    AlertStatus.IN_PROGRESS,
                ]
            )
        )
        .count()
    )

    average = (
        db.query(
            func.avg(
                Indicator.threat_score
            )
        )
        .scalar()
        or 0
    )

    return DashboardSummary(
        total_indicators=total,
        critical_indicators=critical,
        high_indicators=high,
        active_alerts=active_alerts,
        average_threat_score=round(
            float(average),
            2,
        ),
    )