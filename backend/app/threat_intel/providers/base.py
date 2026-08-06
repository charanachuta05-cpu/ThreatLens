from abc import ABC, abstractmethod
from typing import List

from app.threat_intel.schemas import ThreatIndicator


class ThreatProvider(ABC):
    """
    Base class for all Threat Intelligence providers.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Human-readable provider name."""
        pass

    @abstractmethod
    async def collect_indicators(self) -> List[ThreatIndicator]:
        """
        Collect and return normalized indicators.
        """
        pass