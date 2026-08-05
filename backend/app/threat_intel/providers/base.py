from abc import ABC, abstractmethod


class ThreatIntelProvider(ABC):
    """
    Base interface for all threat intelligence providers.
    """

    name: str = "unknown"

    @abstractmethod
    def fetch_indicators(self) -> list[dict]:
        """
        Return a list of threat indicators.
        """

        pass