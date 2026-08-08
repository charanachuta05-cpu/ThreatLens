from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.threat_intel.models import Indicator

from app.dashboard.schemas import DashboardSummary


def get_dashboard_summary(
    db: Session,
) -> DashboardSummary:

    total = db.query(Indicator).count()

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

    alerts = db.query(Alert).count()

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
        active_alerts=alerts,
        average_threat_score=round(
            average,
            2,
        ),
    )