from pydantic import BaseModel


class DashboardAlertTrendPoint(BaseModel):
    date: str
    total: int
    high: int
    critical: int


class DashboardSummary(BaseModel):
    total_indicators: int
    critical_indicators: int
    high_indicators: int
    active_alerts: int
    critical_alerts: int
    average_threat_score: float
    alert_trend: list[DashboardAlertTrendPoint]
