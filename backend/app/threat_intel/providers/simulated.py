from app.threat_intel.providers.base import ThreatProvider
from app.threat_intel.schemas import ThreatIndicator

from app.threat_intel.feed import SIMULATED_FEED


class SimulatedThreatProvider(ThreatProvider):

    @property
    def provider_name(self):
        return "Simulated"

    async def collect_indicators(self):

        indicators = []

        for item in SIMULATED_FEED:

            indicators.append(
                ThreatIndicator(
                    value=item["value"],
                    type=item["indicator_type"],
                    source=self.provider_name,
                    severity=item.get("severity", "medium"),
                    tags=item.get("tags", []),
                )
            )

        return indicators