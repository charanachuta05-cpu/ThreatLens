from app.threat_intel.providers.base import ThreatIntelProvider


class SimulatedThreatProvider(ThreatIntelProvider):

    name = "SimulatedFeed"

    def fetch_indicators(self) -> list[dict]:

        return [
            {
                "indicator_type": "ip",
                "value": "203.0.113.10",
                "severity": "HIGH",
                "source": self.name,
                "description": "Known malicious IP address",
            },
            {
                "indicator_type": "domain",
                "value": "evil-example.com",
                "severity": "CRITICAL",
                "source": self.name,
                "description": "Malicious phishing domain",
            },
            {
                "indicator_type": "ip",
                "value": "198.51.100.250",
                "severity": "CRITICAL",
                "source": self.name,
                "description": "Milestone 5.5 provider validation test"
            },
        ]