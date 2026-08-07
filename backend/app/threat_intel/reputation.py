from app.threat_intel.schemas import ThreatIndicator


def calculate_reputation(
    indicator: ThreatIndicator,
) -> int:
    """
    Calculate an IOC reputation score.

    Version 1:

    malicious × 20
    suspicious × 10

    Maximum score = 100
    """

    score = (
        indicator.malicious * 20
        + indicator.suspicious * 10
    )

    return min(score, 100)