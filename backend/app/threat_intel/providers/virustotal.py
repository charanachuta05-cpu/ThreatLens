import httpx

from app.threat_intel.providers.base import ThreatProvider
from app.threat_intel.schemas import ThreatIndicator


class VirusTotalProvider(ThreatProvider):

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str):
        self.api_key = api_key

    @property
    def provider_name(self):
        return "VirusTotal"

    async def get_ip_report(self, ip: str):

        headers = {
            "x-apikey": self.api_key
        }

        async with httpx.AsyncClient(timeout=20) as client:

            response = await client.get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
                headers=headers,
            )

        response.raise_for_status()

        data = response.json()["data"]
        attr = data["attributes"]

        stats = attr["last_analysis_stats"]

        return ThreatIndicator(
            value=data["id"],
            type="ip",
            source=self.provider_name,
            reputation=attr.get("reputation", 0),
            malicious=stats.get("malicious", 0),
            suspicious=stats.get("suspicious", 0),
            harmless=stats.get("harmless", 0),
            severity="high" if stats.get("malicious", 0) > 0 else "low",
            tags=attr.get("tags", []),
        )

    async def collect_indicators(self):
        """
        Will be expanded later for feed ingestion.
        """
        return []