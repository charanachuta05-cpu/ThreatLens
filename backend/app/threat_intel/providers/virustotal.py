from app.core.config import settings
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
        self.client = ThreatProviderClient(
            api_key,
            timeout=settings.THREAT_PROVIDER_TIMEOUT,
        )

    @property
    def provider_name(self) -> str:
        return "VirusTotal"

    @staticmethod
    def _calculate_severity(
        malicious: int,
        suspicious: int,
    ) -> str:
        """
        Calculate normalized severity from VirusTotal
        analysis statistics.
        """

        if malicious >= 15:
            return "CRITICAL"

        if malicious >= 5:
            return "HIGH"

        if malicious > 0 or suspicious > 0:
            return "MEDIUM"

        return "LOW"

    def _normalize_report(
        self,
        data: dict,
        indicator_type: str,
    ) -> ThreatIndicator:
        """
        Convert a VirusTotal response into the
        normalized ThreatIndicator schema.

        Malformed provider responses are converted into
        a safe ValueError rather than leaking structural
        exceptions such as KeyError or AttributeError.
        """

        if not isinstance(data, dict):
            raise ValueError(
                "Invalid VirusTotal response."
            )

        indicator_id = data.get("id")

        if not isinstance(
            indicator_id,
            str,
        ) or not indicator_id.strip():
            raise ValueError(
                "Invalid VirusTotal response."
            )

        attributes = data.get("attributes")

        if not isinstance(
            attributes,
            dict,
        ):
            raise ValueError(
                "Invalid VirusTotal response."
            )

        stats = attributes.get(
            "last_analysis_stats",
            {},
        )

        if not isinstance(
            stats,
            dict,
        ):
            raise ValueError(
                "Invalid VirusTotal response."
            )

        malicious = stats.get(
            "malicious",
            0,
        )

        suspicious = stats.get(
            "suspicious",
            0,
        )

        harmless = stats.get(
            "harmless",
            0,
        )

        if not all(
            isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
            for value in (
                malicious,
                suspicious,
                harmless,
            )
        ):
            raise ValueError(
                "Invalid VirusTotal response."
            )

        reputation = attributes.get(
            "reputation",
            0,
        )

        if not isinstance(
            reputation,
            (int, float),
        ) or isinstance(
            reputation,
            bool,
        ):
            raise ValueError(
                "Invalid VirusTotal response."
            )

        reputation = max(
            0,
            min(
                int(reputation),
                100,
            ),
        )

        tags = attributes.get(
            "tags",
            [],
        )

        if tags is None:
            tags = []

        if not isinstance(
            tags,
            list,
        ):
            raise ValueError(
                "Invalid VirusTotal response."
            )

        normalized_tags = [
            tag.strip()
            for tag in tags
            if isinstance(
                tag,
                str,
            ) and tag.strip()
        ]

        severity = self._calculate_severity(
            malicious=malicious,
            suspicious=suspicious,
        )

        return ThreatIndicator(
            value=indicator_id,
            type=indicator_type.upper(),
            source=self.provider_name,
            severity=severity,
            reputation=reputation,
            malicious=malicious,
            suspicious=suspicious,
            harmless=harmless,
            tags=normalized_tags,
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

        if not isinstance(
            response,
            dict,
        ):
            raise ValueError(
                "Invalid VirusTotal response."
            )

        return self._normalize_report(
            response.get("data"),
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

        if not isinstance(
            response,
            dict,
        ):
            raise ValueError(
                "Invalid VirusTotal response."
            )

        return self._normalize_report(
            response.get("data"),
            "DOMAIN",
        )

    async def get_url_report(
        self,
        url_id: str,
    ) -> ThreatIndicator:
        """
        Retrieve and normalize a VirusTotal
        URL report.

        VirusTotal expects the URL object ID for
        this endpoint.
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

        if not isinstance(
            response,
            dict,
        ):
            raise ValueError(
                "Invalid VirusTotal response."
            )

        return self._normalize_report(
            response.get("data"),
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

        if not isinstance(
            response,
            dict,
        ):
            raise ValueError(
                "Invalid VirusTotal response."
            )

        return self._normalize_report(
            response.get("data"),
            "HASH",
        )

    async def get_indicator_report(
        self,
        indicator_type: str,
        value: str,
    ) -> ThreatIndicator:
        """
        Generic IOC lookup interface.

        The argument order intentionally matches
        the enrichment service:

            indicator_type, value
        """

        normalized_type = (
            indicator_type.strip().upper()
        )

        if normalized_type == "IP":
            return await self.get_ip_report(
                value
            )

        if normalized_type == "DOMAIN":
            return await self.get_domain_report(
                value
            )

        if normalized_type == "URL":
            return await self.get_url_report(
                value
            )

        if normalized_type == "HASH":
            return await self.get_hash_report(
                value
            )

        raise ValueError(
            f"Unsupported indicator type: "
            f"{indicator_type}"
        )

    async def collect_indicators(
        self,
    ) -> list[ThreatIndicator]:
        """
        VirusTotal currently performs IOC enrichment
        through explicit lookups rather than bulk feed
        collection.
        """

        return []