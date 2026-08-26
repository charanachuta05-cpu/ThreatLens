from pydantic import BaseModel


class DashboardSummary(BaseModel):
    total_indicators: int
    critical_indicators: int
    high_indicators: int
    active_alerts: int
    critical_alerts: int
    average_threat_score: float