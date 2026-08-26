from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.dashboard.schemas import (
    DashboardAlertTrendPoint,
    DashboardSummary,
)
from app.models.alert import Alert, AlertSeverity, AlertStatus
from app.threat_intel.models import Indicator


ACTIVE_ALERT_STATUSES = [
    AlertStatus.OPEN,
    AlertStatus.IN_PROGRESS,
]


def get_dashboard_alert_trend(
    db: Session,
) -> list[DashboardAlertTrendPoint]:
    """
    Return alert creation volume for the last seven UTC
    calendar days, including today.

    The trend counts all created alerts regardless of their
    current status. High includes HIGH and CRITICAL alerts.
    """

    now = datetime.now(timezone.utc)
    today = now.date()

    start_date = today - timedelta(days=6)

    start_datetime = datetime.combine(
        start_date,
        datetime.min.time(),
        tzinfo=timezone.utc,
    )

    end_datetime = datetime.combine(
        today + timedelta(days=1),
        datetime.min.time(),
        tzinfo=timezone.utc,
    )

    alert_date = func.date_trunc(
        "day",
        Alert.created_at,
    )

    rows = (
        db.query(
            alert_date.label("alert_date"),
            func.count(Alert.id).label("total"),
            func.count(Alert.id)
            .filter(
                Alert.severity.in_(
                    [
                        AlertSeverity.HIGH,
                        AlertSeverity.CRITICAL,
                    ]
                )
            )
            .label("high"),
            func.count(Alert.id)
            .filter(
                Alert.severity
                == AlertSeverity.CRITICAL
            )
            .label("critical"),
        )
        .filter(
            Alert.created_at >= start_datetime,
            Alert.created_at < end_datetime,
        )
        .group_by(alert_date)
        .all()
    )

    by_date = {
        row.alert_date.date(): {
            "total": int(row.total),
            "high": int(row.high),
            "critical": int(row.critical),
        }
        for row in rows
    }

    return [
        DashboardAlertTrendPoint(
            date=(
                start_date + timedelta(days=index)
            ).isoformat(),
            total=by_date.get(
                start_date + timedelta(days=index),
                {},
            ).get("total", 0),
            high=by_date.get(
                start_date + timedelta(days=index),
                {},
            ).get("high", 0),
            critical=by_date.get(
                start_date + timedelta(days=index),
                {},
            ).get("critical", 0),
        )
        for index in range(7)
    ]


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
            Alert.status.in_(ACTIVE_ALERT_STATUSES)
        )
        .count()
    )

    critical_alerts = (
        db.query(Alert)
        .filter(
            Alert.status.in_(ACTIVE_ALERT_STATUSES),
            Alert.severity == "CRITICAL",
        )
        .count()
    )

    average = (
        db.query(
            func.avg(Indicator.threat_score)
        )
        .scalar()
        or 0
    )

    return DashboardSummary(
        total_indicators=total,
        critical_indicators=critical,
        high_indicators=high,
        active_alerts=active_alerts,
        critical_alerts=critical_alerts,
        average_threat_score=round(
            float(average),
            2,
        ),
        alert_trend=get_dashboard_alert_trend(db),
    )
