from app.threat_intel.models import ThreatSeverity

SEVERITY_SCORE = {
    ThreatSeverity.LOW.value: 30,
    ThreatSeverity.MEDIUM.value: 60,
    ThreatSeverity.HIGH.value: 85,
    ThreatSeverity.CRITICAL.value: 100,
}


def calculate_threat_score(severity: str) -> int:
    """
    Calculate a threat score based on indicator severity.

    Version 1 scoring model.

    LOW        -> 30
    MEDIUM     -> 60
    HIGH       -> 85
    CRITICAL   -> 100
    """

    return SEVERITY_SCORE.get(
        severity.upper(),
        10,
    )