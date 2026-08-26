# -------------------------------------------------
# Dashboard Authentication
# -------------------------------------------------


def test_dashboard_requires_auth(client):
    response = client.get(
        "/dashboard/summary"
    )

    assert response.status_code == 401


# -------------------------------------------------
# Dashboard RBAC
# -------------------------------------------------


def test_viewer_can_read_dashboard(
    client,
):
    from app.core.security import create_access_token

    token = create_access_token(
        data={
            "sub": "3",
            "email": "viewer@threatlens.com",
            "role": "viewer",
        }
    )

    response = client.get(
        "/dashboard/summary",
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 200


def test_analyst_can_read_dashboard(
    client,
):
    from app.core.security import create_access_token

    token = create_access_token(
        data={
            "sub": "2",
            "email": "analyst@threatlens.com",
            "role": "analyst",
        }
    )

    response = client.get(
        "/dashboard/summary",
        headers={
            "Authorization": f"Bearer {token}"
        },
    )

    assert response.status_code == 200


def test_admin_can_read_dashboard(
    client,
    admin_headers,
):
    response = client.get(
        "/dashboard/summary",
        headers=admin_headers,
    )

    assert response.status_code == 200


# -------------------------------------------------
# Dashboard Response
# -------------------------------------------------


def test_dashboard_returns_expected_fields(
    client,
    admin_headers,
):
    response = client.get(
        "/dashboard/summary",
        headers=admin_headers,
    )

    assert response.status_code == 200

    data = response.json()

    assert "total_indicators" in data
    assert "critical_indicators" in data
    assert "high_indicators" in data
    assert "active_alerts" in data
    assert "average_threat_score" in data

    assert isinstance(
        data["total_indicators"],
        int,
    )

    assert isinstance(
        data["critical_indicators"],
        int,
    )

    assert isinstance(
        data["high_indicators"],
        int,
    )

    assert isinstance(
        data["active_alerts"],
        int,
    )

    assert isinstance(
        data["average_threat_score"],
        (int, float),
    )
    assert "critical_alerts" in data

    assert isinstance(
        data["critical_alerts"],
        int,
    )

def test_dashboard_critical_alerts_only_counts_active_critical(
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

        baseline = baseline_response.json()[
            "critical_alerts"
        ]

        active_critical = Alert(
            title=f"Dashboard Critical Active {unique}",
            description="Critical active dashboard test.",
            severity="CRITICAL",
            status=AlertStatus.OPEN,
            source="pytest",
            created_by=1,
        )

        resolved_critical = Alert(
            title=f"Dashboard Critical Resolved {unique}",
            description="Critical resolved dashboard test.",
            severity="CRITICAL",
            status=AlertStatus.RESOLVED,
            source="pytest",
            created_by=1,
        )

        active_high = Alert(
            title=f"Dashboard High Active {unique}",
            description="High active dashboard test.",
            severity="HIGH",
            status=AlertStatus.OPEN,
            source="pytest",
            created_by=1,
        )

        db.add_all(
            [
                active_critical,
                resolved_critical,
                active_high,
            ]
        )

        db.commit()

        response = client.get(
            "/dashboard/summary",
            headers=admin_headers,
        )

        assert response.status_code == 200

        data = response.json()

        assert data["critical_alerts"] == baseline + 1

    finally:
        db.query(Alert).filter(
            Alert.title.in_(
                [
                    f"Dashboard Critical Active {unique}",
                    f"Dashboard Critical Resolved {unique}",
                    f"Dashboard High Active {unique}",
                ]
            )
        ).delete(
            synchronize_session=False
        )

        db.commit()
        db.close()