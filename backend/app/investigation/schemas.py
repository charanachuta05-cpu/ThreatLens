from pydantic import BaseModel


class InvestigationScores(BaseModel):
    threat_score: int
    reputation_score: int
    confidence_score: int


class InvestigationResponse(BaseModel):
    indicator: dict
    scores: InvestigationScores
    tags: list[str]
    related_indicators: list[dict]
    alerts: list[dict]
    recommendation: Recommendation

class Recommendation(BaseModel):
    summary: str
    priority: str
    actions: list[str]