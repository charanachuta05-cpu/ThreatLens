from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class AlertSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"


class AlertCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    description: str = Field(..., min_length=5)
    severity: AlertSeverity
    source: str = Field(..., min_length=2, max_length=100)
    assigned_to: int | None = None


class AlertUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=255)
    description: str | None = Field(default=None, min_length=5)
    severity: AlertSeverity | None = None
    status: AlertStatus | None = None
    source: str | None = Field(default=None, min_length=2, max_length=100)
    assigned_to: int | None = None


class AlertResponse(BaseModel):
    id: int
    title: str
    description: str
    severity: AlertSeverity
    status: AlertStatus
    source: str
    created_by: int
    assigned_to: int | None
    created_at: datetime
    updated_at: datetime | None

    model_config = ConfigDict(from_attributes=True)