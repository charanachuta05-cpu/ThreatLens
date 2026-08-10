from app.threat_intel.providers.base import ThreatProvider
from app.threat_intel.providers.client import ThreatProviderClient
from app.threat_intel.schemas import ThreatIndicator


class VirusTotalProvider(ThreatProvider):
    """
    VirusTotal threat intelligence provider.
    """

    BASE_URL = "https://www.virustotal.com/api/v3"

    def __init__(
        self,
        api_key: str,
    ):
        self.client = ThreatProviderClient(api_key)

    @property
    def provider_name(self) -> str:
        return "VirusTotal"

    def _normalize_report(
        self,
        data: dict,
        indicator_type: str,
    ) -> ThreatIndicator:
        """
        Convert a VirusTotal response into the
        normalized ThreatIndicator schema.
        """

        attributes = data.get("attributes", {})

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

        reputation = attributes.get(
            "reputation",
            0,
        )

        reputation = max(
            0,
            min(reputation, 100),
        )

        return ThreatIndicator(
            value=data["id"],
            type=indicator_type,
            source=self.provider_name,
            severity=severity,
            reputation=reputation,
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

        return self._normalize_report(
            response["data"],
            "IP",
        )

    async def get_domain_report(
        self,
        domain: str,
    ) -> ThreatIndicator:
        """
        Retrieve and normalize a VirusTotal
        domain reputation report.
        """

        response = await self.client.get(
            url=(
                f"{self.BASE_URL}"
                f"/domains/{domain}"
            ),
            headers={
                "x-apikey": self.client.api_key,
            },
        )

        return self._normalize_report(
            response["data"],
            "DOMAIN",
        )

    async def get_url_report(
        self,
        url_id: str,
    ) -> ThreatIndicator:
        """
        Retrieve and normalize a VirusTotal
        URL report.

        VirusTotal URL objects use their URL
        identifier rather than the raw URL in
        the API path.
        """

        response = await self.client.get(
            url=(
                f"{self.BASE_URL}"
                f"/urls/{url_id}"
            ),
            headers={
                "x-apikey": self.client.api_key,
            },
        )

        return self._normalize_report(
            response["data"],
            "URL",
        )

    async def get_hash_report(
        self,
        file_hash: str,
    ) -> ThreatIndicator:
        """
        Retrieve and normalize a VirusTotal
        file hash report.
        """

        response = await self.client.get(
            url=(
                f"{self.BASE_URL}"
                f"/files/{file_hash}"
            ),
            headers={
                "x-apikey": self.client.api_key,
            },
        )

        return self._normalize_report(
            response["data"],
            "HASH",
        )

    async def get_indicator_report(
        self,
        indicator_type: str,
        value: str,
    ) -> ThreatIndicator:
        """
        Generic IOC lookup interface.
        """

        normalized_type = indicator_type.strip().upper()

        if normalized_type == "IP":
            return await self.get_ip_report(value)

        if normalized_type == "DOMAIN":
            return await self.get_domain_report(value)

        if normalized_type == "URL":
            return await self.get_url_report(value)

        if normalized_type == "HASH":
            return await self.get_hash_report(value)

        raise ValueError(
            f"Unsupported indicator type: "
            f"{indicator_type}"
        )

    async def collect_indicators(
        self,
    ) -> list[ThreatIndicator]:
        """
        Bulk feed collection placeholder.

        VirusTotal currently performs IOC
        enrichment through explicit lookups.
        """

        return []