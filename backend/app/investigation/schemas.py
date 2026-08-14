from enum import Enum

from pydantic import BaseModel, Field


class RecommendationPriority(str, Enum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"


class Recommendation(BaseModel):
    summary: str
    priority: RecommendationPriority
    actions: list[str]


class InvestigationIndicator(BaseModel):
    id: int
    value: str
    type: str
    severity: str
    source: str


class InvestigationScores(BaseModel):
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


class RelatedIndicator(BaseModel):
    id: int
    value: str
    indicator_type: str
    severity: str
    source: str
    correlation_score: int = Field(
        ge=0,
        le=100,
    )
    reasons: list[str]


class InvestigationAlert(BaseModel):
    id: int
    title: str


class InvestigationResponse(BaseModel):
    indicator: InvestigationIndicator
    scores: InvestigationScores
    tags: list[str]
    related_indicators: list[RelatedIndicator]
    alerts: list[InvestigationAlert]
    recommendation: Recommendation