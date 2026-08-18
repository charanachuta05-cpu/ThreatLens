from sqlalchemy.exc import SQLAlchemyError


def test_global_exception_handler_does_not_expose_internal_error(
    client,
    admin_headers,
    monkeypatch,
):
    from app.api.routes import investigations

    sensitive_message = (
        "SECRET_INTERNAL_DETAILS: "
        "postgres://internal-db.example.com/super-secret"
    )

    def raise_unexpected_error(db, indicator_id):
        raise RuntimeError(sensitive_message)

    monkeypatch.setattr(
        investigations,
        "investigate_indicator",
        raise_unexpected_error,
    )

    # TestClient normally re-raises unhandled server exceptions.
    # Disable that behaviour so we can verify the actual HTTP response.
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(
        app,
        raise_server_exceptions=False,
    ) as test_client:
        response = test_client.get(
            "/investigations/999999",
            headers=admin_headers,
        )

    assert response.status_code == 500

    data = response.json()

    assert data["success"] is False
    assert data["error"]["code"] == 500
    assert data["error"]["type"] == "InternalServerError"
    assert data["error"]["message"] == "Unexpected server error."

    assert sensitive_message not in response.text
    assert "SECRET_INTERNAL_DETAILS" not in response.text
    assert "super-secret" not in response.text
    assert "internal-db.example.com" not in response.text


def test_database_exception_handler_does_not_expose_database_details(
    client,
    admin_headers,
    monkeypatch,
):
    from app.api.routes import investigations

    sensitive_message = (
        "DB_PASSWORD=super-secret "
        "host=internal-db.example.com "
        "database=threatlens_prod"
    )

    def raise_database_error(db, indicator_id):
        raise SQLAlchemyError(sensitive_message)

    monkeypatch.setattr(
        investigations,
        "investigate_indicator",
        raise_database_error,
    )

    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(
        app,
        raise_server_exceptions=False,
    ) as test_client:
        response = test_client.get(
            "/investigations/999999",
            headers=admin_headers,
        )

    assert response.status_code == 500

    data = response.json()

    assert data["success"] is False
    assert data["error"]["code"] == 500
    assert data["error"]["type"] == "DatabaseError"
    assert data["error"]["message"] == "Database operation failed."

    assert sensitive_message not in response.text
    assert "DB_PASSWORD" not in response.text
    assert "super-secret" not in response.text
    assert "internal-db.example.com" not in response.text
    assert "threatlens_prod" not in response.text
