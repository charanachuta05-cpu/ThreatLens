import pytest
from pydantic import ValidationError

from app.core.config import Settings


def make_settings(**overrides):
    values = {
        "APP_NAME": "ThreatLens",
        "APP_ENV": "development",
        "DEBUG": True,
        "DATABASE_URL": "postgresql+psycopg://postgres:test@127.0.0.1:5432/threatlens_db",
        "SECRET_KEY": "development-secret-key-for-tests",
    }
    values.update(overrides)

    return Settings(_env_file=None, **values)


def test_development_configuration_is_allowed():
    settings = make_settings()

    assert settings.APP_ENV == "development"
    assert settings.DEBUG is True


def test_test_configuration_is_allowed():
    settings = make_settings(
        APP_ENV="test",
        DEBUG=False,
    )

    assert settings.APP_ENV == "test"
    assert settings.DEBUG is False


def test_production_configuration_requires_debug_disabled():
    with pytest.raises(ValidationError, match="DEBUG"):
        make_settings(
            APP_ENV="production",
            DEBUG=True,
            SECRET_KEY="secure-production-secret-key",
        )


def test_production_configuration_rejects_placeholder_secret():
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        make_settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="CHANGE_ME_TO_A_LONG_RANDOM_SECRET",
        )


def test_production_configuration_requires_nontrivial_secret():
    with pytest.raises(ValidationError, match="SECRET_KEY"):
        make_settings(
            APP_ENV="production",
            DEBUG=False,
            SECRET_KEY="short",
        )


def test_production_configuration_is_allowed_when_secure():
    settings = make_settings(
        APP_ENV="production",
        DEBUG=False,
        SECRET_KEY="a-long-random-production-secret-key",
    )

    assert settings.APP_ENV == "production"
    assert settings.DEBUG is False


def test_environment_name_is_normalized():
    settings = make_settings(
        APP_ENV=" Production ",
        DEBUG=False,
    )

    assert settings.APP_ENV == "production"
    assert settings.DEBUG is False


def test_invalid_environment_is_rejected():
    with pytest.raises(ValidationError, match="APP_ENV"):
        make_settings(APP_ENV="staging")
