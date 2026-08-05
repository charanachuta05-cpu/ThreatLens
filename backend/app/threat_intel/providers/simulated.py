from app.threat_intel.providers.base import ThreatProvider


class SimulatedThreatProvider(ThreatProvider):
    """
    Development threat intelligence provider.

    Used for testing ingestion,
    alert generation, and WebSocket delivery.
    """

    name = "SimulatedProvider"


    def collect_indicators(self) -> list[dict]:
        """
        Return simulated threat indicators.
        """

        return [
            {
                "indicator_type": "ip",
                "value": "203.0.113.10",
                "severity": "HIGH",
                "source": self.name,
                "description": "Suspicious IP activity detected",
            },
            {
                "indicator_type": "domain",
                "value": "evil-example.com",
                "severity": "CRITICAL",
                "source": self.name,
                "description": "Malicious domain detected",
            },
        ]