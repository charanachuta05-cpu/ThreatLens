from app.threat_intel.correlation import correlate_indicators
from app.threat_intel.schemas import ThreatIndicator


def test_high_correlation():
    first = ThreatIndicator(
        value="1.1.1.1",
        type="IP",
        source="VirusTotal",
        severity="HIGH",
        reputation=80,
        malicious=5,
        suspicious=1,
        harmless=0,
        tags=["botnet", "c2"],
    )

    second = ThreatIndicator(
        value="2.2.2.2",
        type="IP",
        source="VirusTotal",
        severity="HIGH",
        reputation=75,
        malicious=6,
        suspicious=1,
        harmless=0,
        tags=["c2"],
    )

    result = correlate_indicators(first, second)

    assert result.related is True
    assert result.score >= 80