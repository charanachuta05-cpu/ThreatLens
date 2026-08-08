from app.threat_intel.schemas import ThreatSeverity


SEVERITY_SCORE = {
    ThreatSeverity.LOW.value: 30,
    ThreatSeverity.MEDIUM.value: 60,
    ThreatSeverity.HIGH.value: 85,
    ThreatSeverity.CRITICAL.value: 100,
}


def calculate_threat_score(
    severity: str,
) -> int:
    """
    Calculate threat score from indicator severity.

    LOW      -> 30
    MEDIUM   -> 60
    HIGH     -> 85
    CRITICAL -> 100
    """

    if not isinstance(severity, str):
        return 10

    return SEVERITY_SCORE.get(
        severity.strip().upper(),
        10,
    )