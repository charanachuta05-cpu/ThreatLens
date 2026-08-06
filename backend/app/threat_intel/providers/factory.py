from app.core.config import settings

from app.threat_intel.providers.simulated import (
    SimulatedThreatProvider,
)

from app.threat_intel.providers.virustotal import (
    VirusTotalProvider,
)


def get_providers():

    providers = [
        SimulatedThreatProvider(),
    ]

    if settings.VIRUSTOTAL_ENABLED:

        providers.append(
            VirusTotalProvider(
                settings.VIRUSTOTAL_API_KEY
            )
        )

    return providers