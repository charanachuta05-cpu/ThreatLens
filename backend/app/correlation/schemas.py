from pydantic import BaseModel, Field


class CorrelationIndicator(BaseModel):
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
    tags: list[str]


class CorrelatedIndicator(BaseModel):
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
    correlation_score: int = Field(
        ge=0,
        le=100,
    )
    reasons: list[str]


class CorrelationAlert(BaseModel):
    id: int
    title: str
    severity: str
    status: str
    indicator_id: int | None = None


class CorrelationSummary(BaseModel):
    total_indicators_compared: int = Field(
        ge=0,
    )
    related_indicators: int = Field(
        ge=0,
    )
    strong_correlations: int = Field(
        ge=0,
    )
    related_alerts: int = Field(
        ge=0,
    )
    highest_correlation_score: int = Field(
        ge=0,
        le=100,
    )


class CorrelationResponse(BaseModel):
    indicator: CorrelationIndicator
    summary: CorrelationSummary
    related_indicators: list[CorrelatedIndicator]
    alerts: list[CorrelationAlert]