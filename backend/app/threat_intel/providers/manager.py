from app.threat_intel.providers.base import ThreatProvider
from app.threat_intel.providers.simulated import (
    SimulatedThreatProvider,
)


class ThreatProviderManager:
    """
    Coordinates multiple threat intelligence providers.
    """


    def __init__(self):

        self.providers: list[ThreatProvider] = [
            SimulatedThreatProvider(),
        ]


    def collect_indicators(self) -> list[dict]:
        """
        Collect indicators from all registered providers.
        """

        indicators = []


        for provider in self.providers:

            indicators.extend(
                provider.collect_indicators()
            )


        return indicators