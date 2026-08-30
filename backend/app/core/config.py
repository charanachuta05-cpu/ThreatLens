from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # Application
    APP_NAME: str
    APP_ENV: str
    DEBUG: bool

    # Database
    DATABASE_URL: str

    # Security
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # CORS
    CORS_ORIGINS: str = (
        "http://localhost:5173,http://127.0.0.1:5173"
    )

    @property
    def cors_origins(self) -> list[str]:
        return [
            origin.strip()
            for origin in self.CORS_ORIGINS.split(",")
            if origin.strip()
        ]

    # Threat Intelligence
    VIRUSTOTAL_API_KEY: str = ""
    VIRUSTOTAL_ENABLED: bool = False
    THREAT_PROVIDER_TIMEOUT: float = 20.0

    ABUSEIPDB_API_KEY: str = ""
    ABUSEIPDB_ENABLED: bool = False

    OTX_API_KEY: str = ""
    OTX_ENABLED: bool = False

    THREAT_INTEL_INGEST_INTERVAL_MINUTES: int = 5

    # Email Notifications
    EMAIL_NOTIFICATIONS_ENABLED: bool = False
    ACCESS_REQUEST_ADMIN_EMAIL: str = ""
    RESEND_API_KEY: str = ""
    EMAIL_FROM: str = "ThreatLens Security <onboarding@resend.dev>"
    FRONTEND_URL: str = "http://localhost:5173"
    EMAIL_TIMEOUT_SECONDS: float = 5.0

    @model_validator(mode="after")
    def validate_security_configuration(self):
        allowed_environments = {
            "development",
            "test",
            "production",
        }

        environment = self.APP_ENV.strip().lower()
        self.APP_ENV = environment

        if environment not in allowed_environments:
            raise ValueError(
                "APP_ENV must be one of: development, test, production"
            )

        if environment == "production":
            if self.DEBUG:
                raise ValueError(
                    "DEBUG must be false when APP_ENV is production"
                )

            if (
                not self.SECRET_KEY
                or len(self.SECRET_KEY) < 32
                or self.SECRET_KEY
                == "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
            ):
                raise ValueError(
                    "SECRET_KEY must be a secure value of at least 32 characters "
                    "when APP_ENV is production"
                )

        return self

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[2] / ".env",
        case_sensitive=False,
    )


settings = Settings()