from app.threat_intel.providers.base import ThreatProvider
from app.threat_intel.providers.client import ThreatProviderClient
from app.threat_intel.schemas import ThreatIndicator


class VirusTotalProvider(ThreatProvider):
    """
    VirusTotal threat intelligence provider.
    """

    BASE_URL = (
        "https://www.virustotal.com/api/v3"
    )

    def __init__(
        self,
        api_key: str,
    ):
        self.client = ThreatProviderClient(
            api_key
        )

    @property
    def provider_name(self) -> str:
        return "VirusTotal"

    async def get_ip_report(
        self,
        ip: str,
    ) -> ThreatIndicator:
        """
        Retrieve and normalize a VirusTotal
        IP reputation report.
        """

        response = await self.client.get(
            url=(
                f"{self.BASE_URL}"
                f"/ip_addresses/{ip}"
            ),
            headers={
                "x-apikey": self.client.api_key,
            },
        )

        data = response["data"]
        attributes = data["attributes"]

        stats = attributes.get(
            "last_analysis_stats",
            {},
        )

        malicious = stats.get(
            "malicious",
            0,
        )

        suspicious = stats.get(
            "suspicious",
            0,
        )

        if malicious >= 15:
            severity = "CRITICAL"

        elif malicious >= 5:
            severity = "HIGH"

        elif malicious > 0 or suspicious > 0:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        return ThreatIndicator(
            value=data["id"],
            type="IP",
            source=self.provider_name,
            severity=severity,
            reputation=max(
                0,
                min(
                    attributes.get(
                        "reputation",
                        0,
                    ),
                    100,
                ),
            ),
            malicious=malicious,
            suspicious=suspicious,
            harmless=stats.get(
                "harmless",
                0,
            ),
            tags=attributes.get(
                "tags",
                [],
            ),
        )

    async def collect_indicators(
        self,
    ) -> list[ThreatIndicator]:
        """
        Bulk feed collection placeholder.

        Individual IOC lookup is currently
        supported through get_ip_report().
        """

        return []