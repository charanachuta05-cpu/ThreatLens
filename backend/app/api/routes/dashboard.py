from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies.auth import require_roles
from app.core.database import get_db
from app.dashboard.service import get_dashboard_summary
from app.models.user import User

router = APIRouter(
    prefix="/dashboard",
    tags=["Dashboard"],
)


@router.get("/summary")
def summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_roles("admin", "analyst", "viewer")
    ),
):
    return get_dashboard_summary(db)

def test_dashboard_counts_only_active_alerts(
    client,
    admin_headers,
):
    from app.core.database import SessionLocal
    from app.models.alert import Alert, AlertStatus

    db = SessionLocal()

    try:
        active_alert = Alert(
            title="Dashboard Active Alert",
            description="Active dashboard test alert.",
            severity="HIGH",
            status=AlertStatus.OPEN,
            source="pytest",
            created_by=1,
        )

        resolved_alert = Alert(
            title="Dashboard Resolved Alert",
            description="Resolved dashboard test alert.",
            severity="HIGH",
            status=AlertStatus.RESOLVED,
            source="pytest",
            created_by=1,
        )

        db.add_all(
            [
                active_alert,
                resolved_alert,
            ]
        )
        db.commit()

    finally:
        db.close()

    response = client.get(
        "/dashboard/summary",
        headers=admin_headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert data["active_alerts"] >= 1

def test_dashboard_counts_only_active_alerts(
    client,
    admin_headers,
):
    from uuid import uuid4

    from app.core.database import SessionLocal
    from app.models.alert import Alert, AlertStatus

    unique = uuid4().hex[:8]

    db = SessionLocal()

    try:
        baseline_response = client.get(
            "/dashboard/summary",
            headers=admin_headers,
        )

        assert baseline_response.status_code == 200

        baseline_active_alerts = (
            baseline_response.json()["active_alerts"]
        )

        active_alert = Alert(
            title=f"Dashboard Active {unique}",
            description="Active dashboard regression test.",
            severity="HIGH",
            status=AlertStatus.OPEN,
            source="pytest",
            created_by=1,
        )

        resolved_alert = Alert(
            title=f"Dashboard Resolved {unique}",
            description="Resolved dashboard regression test.",
            severity="HIGH",
            status=AlertStatus.RESOLVED,
            source="pytest",
            created_by=1,
        )

        db.add_all(
            [
                active_alert,
                resolved_alert,
            ]
        )

        db.commit()

        response = client.get(
            "/dashboard/summary",
            headers=admin_headers,
        )

        assert response.status_code == 200

        active_alerts = response.json()[
            "active_alerts"
        ]

        assert active_alerts == (
            baseline_active_alerts + 1
        )

    finally:
        db.query(Alert).filter(
            Alert.title.in_(
                [
                    f"Dashboard Active {unique}",
                    f"Dashboard Resolved {unique}",
                ]
            )
        ).delete(
            synchronize_session=False
        )

        db.commit()
        db.close()