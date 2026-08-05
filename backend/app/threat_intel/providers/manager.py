from app.threat_intel.providers.simulated import (
    SimulatedThreatProvider,
)


class ThreatProviderManager:
    """
    Manages all threat intelligence providers.
    """

    def __init__(self):

        self.providers = [
            SimulatedThreatProvider()
        ]


    def collect_indicators(self) -> list[dict]:

        indicators = []

        for provider in self.providers:

            indicators.extend(
                provider.fetch_indicators()
            )

        return indicators