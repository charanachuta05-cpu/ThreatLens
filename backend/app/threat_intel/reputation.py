from app.threat_intel.schemas import ThreatIndicator


def calculate_reputation(
    indicator: ThreatIndicator,
) -> int:
    """
    Calculate IOC reputation score.

    malicious × 20
    suspicious × 10

    Maximum = 100.
    """

    score = (
        indicator.malicious * 20
        + indicator.suspicious * 10
    )

    return min(
        max(score, 0),
        100,
    )