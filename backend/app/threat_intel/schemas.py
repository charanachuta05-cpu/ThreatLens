from datetime import datetime
from enum import Enum

from pydantic import (
    BaseModel,
    Field,
    field_validator,
)


class IndicatorType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH = "HASH"


class ThreatSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class IndicatorCreate(BaseModel):
    indicator_type: IndicatorType

    value: str = Field(
        min_length=1,
        max_length=255,
    )

    severity: ThreatSeverity

    source: str = Field(
        min_length=1,
        max_length=100,
    )

    description: str | None = Field(
        default=None,
        max_length=500,
    )

    @field_validator("value")
    @classmethod
    def normalize_value(
        cls,
        value: str,
    ) -> str:
        value = value.strip()

        if not value:
            raise ValueError(
                "Indicator value cannot be empty."
            )

        return value

    @field_validator("source")
    @classmethod
    def normalize_source(
        cls,
        value: str,
    ) -> str:
        value = value.strip()

        if not value:
            raise ValueError(
                "Source cannot be empty."
            )

        return value


class IndicatorResponse(IndicatorCreate):
    id: int

    threat_score: int = Field(
        ge=0,
        le=100,
    )

    reputation_score: int = Field(
        ge=0,
        le=100,
    )

    confidence_score: int = Field(
        ge=0,
        le=100,
    )

    tags: list[str] = Field(
        default_factory=list,
    )

    created_at: datetime

    model_config = {
        "from_attributes": True,
    }

    @field_validator(
        "indicator_type",
        mode="before",
    )
    @classmethod
    def normalize_indicator_type(
        cls,
        value,
    ):
        if isinstance(
            value,
            IndicatorType,
        ):
            return value

        if isinstance(
            value,
            str,
        ):
            normalized = value.strip().upper()

            if normalized in {
                "IP",
                "DOMAIN",
                "URL",
                "HASH",
            }:
                return normalized

        return value

    @field_validator(
        "tags",
        mode="before",
    )
    @classmethod
    def normalize_tags(
        cls,
        value,
    ):
        """
        Convert database CSV string into API list.

        Example:

        "ip,high,high-risk"

        becomes:

        ["ip", "high", "high-risk"]
        """

        if value is None:
            return []

        if isinstance(
            value,
            list,
        ):
            return [
                str(tag).strip()
                for tag in value
                if str(tag).strip()
            ]

        if isinstance(
            value,
            str,
        ):
            if not value.strip():
                return []

            return [
                tag.strip()
                for tag in value.split(",")
                if tag.strip()
            ]

        return []


class ThreatIndicator(BaseModel):
    """
    Common normalized format returned
    by threat intelligence providers and
    consumed by the enrichment/correlation engines.
    """

    value: str

    type: str

    source: str

    severity: str = "LOW"

    reputation: int = Field(
        default=0,
        ge=0,
        le=100,
    )

    confidence: int = Field(
        default=0,
        ge=0,
        le=100,
    )

    malicious: int = Field(
        default=0,
        ge=0,
    )

    suspicious: int = Field(
        default=0,
        ge=0,
    )

    harmless: int = Field(
        default=0,
        ge=0,
    )

    tags: list[str] = Field(
        default_factory=list,
    )

    @field_validator(
        "value",
        "source",
        "type",
        mode="before",
    )
    @classmethod
    def normalize_strings(
        cls,
        value,
    ):
        if isinstance(
            value,
            str,
        ):
            return value.strip()

        return value

    @field_validator(
        "severity",
        mode="before",
    )
    @classmethod
    def normalize_severity(
        cls,
        value,
    ):
        if isinstance(
            value,
            str,
        ):
            return value.strip().upper()

        return value

    @field_validator(
        "tags",
        mode="before",
    )
    @classmethod
    def normalize_provider_tags(
        cls,
        value,
    ):
        if value is None:
            return []

        if isinstance(
            value,
            str,
        ):
            return [
                tag.strip()
                for tag in value.split(",")
                if tag.strip()
            ]

        return value