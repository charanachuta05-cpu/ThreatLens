from datetime import datetime
from enum import Enum

from pydantic import BaseModel


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
    created_at: datetime

    model_config = {
        "from_attributes": True
    }