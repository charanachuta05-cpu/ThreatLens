from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


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
    value: str
    severity: ThreatSeverity
    source: str
    description: str | None = None


class IndicatorResponse(IndicatorCreate):
    id: int

    threat_score: int

    reputation_score: int

    created_at: datetime

    model_config = {
        "from_attributes": True
    }


# Provider normalized threat intelligence schema
class ThreatIndicator(BaseModel):
    """
    Common format returned by threat intelligence providers.
    """

    value: str
    type: str
    source: str

    severity: str = "LOW"

    reputation: int = 0

    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0

    tags: list[str] = Field(default_factory=list)