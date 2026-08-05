from abc import ABC, abstractmethod


class ThreatProvider(ABC):
    """
    Base interface for all threat intelligence providers.

    Every provider (Simulated, VirusTotal, MISP, OTX, etc.)
    must implement this contract.
    """

    name: str = "unknown"


    @abstractmethod
    def collect_indicators(self) -> list[dict]:
        """
        Collect threat indicators from the provider.

        Returns:
            List of normalized indicator dictionaries.

        Example:
            [
                {
                    "indicator_type": "ip",
                    "value": "192.168.1.10",
                    "severity": "HIGH",
                    "source": "ProviderName",
                    "description": "Malicious activity detected"
                }
            ]
        """

        pass