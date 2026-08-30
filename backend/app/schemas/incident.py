from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.models.incident import (
    IncidentPriority,
    IncidentStatus,
)


class IncidentCreate(BaseModel):
    title: str = Field(
        min_length=3,
        max_length=255,
    )

    description: str = Field(
        min_length=1,
    )

    priority: IncidentPriority = IncidentPriority.MEDIUM

    assigned_to: int | None = Field(
        default=None,
        ge=1,
    )

    alert_ids: list[int] = Field(
        default_factory=list,
    )

    indicator_ids: list[int] = Field(
        default_factory=list,
    )

    @field_validator("alert_ids", "indicator_ids")
    @classmethod
    def validate_ids(
        cls,
        values: list[int],
    ) -> list[int]:
        if any(value < 1 for value in values):
            raise ValueError("Related IDs must be positive integers.")

        # Remove duplicates while preserving client order.
        return list(dict.fromkeys(values))


class IncidentUpdate(BaseModel):
    title: str | None = Field(
        default=None,
        min_length=3,
        max_length=255,
    )

    description: str | None = Field(
        default=None,
        min_length=1,
    )

    priority: IncidentPriority | None = None

    status: IncidentStatus | None = None

    assigned_to: int | None = Field(
        default=None,
        ge=1,
    )


class IncidentNoteCreate(BaseModel):
    content: str = Field(
        min_length=1,
        max_length=5000,
    )

    @field_validator("content")
    @classmethod
    def normalize_content(
        cls,
        value: str,
    ) -> str:
        value = value.strip()

        if not value:
            raise ValueError("Incident note cannot be empty.")

        return value


class IncidentNoteResponse(BaseModel):
    id: int
    incident_id: int
    author_id: int
    content: str
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(
        from_attributes=True,
    )


class IncidentAlertResponse(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    indicator_id: int | None

    model_config = ConfigDict(
        from_attributes=True,
    )


class IncidentIndicatorResponse(BaseModel):
    id: int
    value: str
    indicator_type: str
    severity: str
    source: str
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

    model_config = ConfigDict(
        from_attributes=True,
    )


class IncidentResponse(BaseModel):
    id: int
    title: str
    description: str
    priority: IncidentPriority
    status: IncidentStatus
    created_by: int
    assigned_to: int | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None

    alerts: list[IncidentAlertResponse] = Field(
        default_factory=list,
    )

    indicators: list[IncidentIndicatorResponse] = Field(
        default_factory=list,
    )

    notes: list[IncidentNoteResponse] = Field(
        default_factory=list,
    )

    model_config = ConfigDict(
        from_attributes=True,
    )
