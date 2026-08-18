from sqlalchemy import text


class FailingConnection:
    def __enter__(self):
        raise RuntimeError(
            "SECRET_DATABASE_DETAILS password=super-secret "
            "host=internal-db.example.com"
        )

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FailingEngine:
    def connect(self):
        return FailingConnection()


def test_health_does_not_expose_database_exception(client, monkeypatch):
    from app import main

    monkeypatch.setattr(main, "engine", FailingEngine())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "unhealthy",
        "database": "disconnected",
    }

    response_text = response.text

    assert "SECRET_DATABASE_DETAILS" not in response_text
    assert "super-secret" not in response_text
    assert "internal-db.example.com" not in response_text
