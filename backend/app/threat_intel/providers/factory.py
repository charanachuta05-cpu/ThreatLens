from app.core.config import settings

from app.threat_intel.providers.simulated import (
    SimulatedThreatProvider,
)
from app.threat_intel.providers.virustotal import (
    VirusTotalProvider,
)


def get_providers():
    """
    Build the list of enabled threat intelligence
    providers from application configuration.
    """

    providers = [
        SimulatedThreatProvider(),
    ]

    if (
        settings.VIRUSTOTAL_ENABLED
        and settings.VIRUSTOTAL_API_KEY
    ):
        providers.append(
            VirusTotalProvider(
                settings.VIRUSTOTAL_API_KEY
            )
        )

    return providers