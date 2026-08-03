from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class IndicatorType(str, Enum):
    IP = "IP"
    DOMAIN = "DOMAIN"
    HASH = "HASH"
    URL = "URL"
    EMAIL = "EMAIL"


class ThreatSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ThreatIndicatorCreate(BaseModel):
    """
    Schema for creating a threat indicator.
    """

    indicator_type: IndicatorType = Field(
        ...,
        description="Type of threat indicator"
    )

    value: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Threat indicator value"
    )

    severity: ThreatSeverity = Field(
        default=ThreatSeverity.LOW,
        description="Threat severity level"
    )

    source: str = Field(
        ...,
        min_length=2,
        max_length=100,
        description="Threat intelligence source"
    )

    description: str | None = Field(
        default=None,
        description="Threat description"
    )


class ThreatIndicatorUpdate(BaseModel):
    """
    Schema for updating a threat indicator.
    """

    indicator_type: IndicatorType | None = Field(
        default=None,
        description="Updated indicator type"
    )

    value: str | None = Field(
        default=None,
        min_length=3,
        max_length=255,
        description="Updated indicator value"
    )

    severity: ThreatSeverity | None = Field(
        default=None,
        description="Updated threat severity"
    )

    source: str | None = Field(
        default=None,
        min_length=2,
        max_length=100,
        description="Updated threat source"
    )

    description: str | None = Field(
        default=None,
        description="Updated threat description"
    )


class ThreatIndicatorResponse(BaseModel):
    """
    Schema for returning threat indicator data.
    """

    id: int

    indicator_type: IndicatorType

    value: str

    severity: ThreatSeverity

    source: str

    description: str | None

    created_at: datetime

    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True
    )