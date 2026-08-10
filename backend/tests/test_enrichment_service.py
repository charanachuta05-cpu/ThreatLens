import pytest

from app.threat_intel.enrichment_service import (
    enrich_with_providers,
)
from app.threat_intel.schemas import ThreatIndicator


class SuccessfulProvider:
    @property
    def provider_name(self):
        return "SuccessfulProvider"

    async def get_indicator_report(
        self,
        indicator_type: str,
        value: str,
    ):
        return ThreatIndicator(
            value=value,
            type=indicator_type,
            source=self.provider_name,
            severity="HIGH",
            reputation=80,
            malicious=4,
            suspicious=2,
            harmless=10,
            tags=["malware", "c2"],
        )


class FailingProvider:
    @property
    def provider_name(self):
        return "FailingProvider"

    async def get_indicator_report(
        self,
        indicator_type: str,
        value: str,
    ):
        raise RuntimeError(
            "Simulated provider failure"
        )


class EmptyProvider:
    @property
    def provider_name(self):
        return "EmptyProvider"

    async def get_indicator_report(
        self,
        indicator_type: str,
        value: str,
    ):
        return None


@pytest.mark.asyncio
async def test_successful_provider_returns_enrichment():
    indicator = ThreatIndicator(
        value="203.0.113.10",
        type="IP",
        source="Test",
        severity="MEDIUM",
    )

    result = await enrich_with_providers(
        indicator,
        providers=[
            SuccessfulProvider(),
        ],
    )

    assert result is not None

    assert result.value == "203.0.113.10"
    assert result.type == "IP"
    assert result.source == "SuccessfulProvider"

    assert result.severity == "HIGH"
    assert result.reputation == 80
    assert result.malicious == 4
    assert result.suspicious == 2
    assert result.harmless == 10

    assert "malware" in result.tags
    assert "c2" in result.tags


@pytest.mark.asyncio
async def test_provider_failure_does_not_stop_enrichment():
    indicator = ThreatIndicator(
        value="203.0.113.20",
        type="IP",
        source="Test",
        severity="MEDIUM",
    )

    result = await enrich_with_providers(
        indicator,
        providers=[
            FailingProvider(),
            SuccessfulProvider(),
        ],
    )

    assert result is not None
    assert result.value == "203.0.113.20"
    assert result.source == "SuccessfulProvider"
    assert result.severity == "HIGH"


@pytest.mark.asyncio
async def test_empty_provider_result_is_skipped():
    indicator = ThreatIndicator(
        value="203.0.113.30",
        type="IP",
        source="Test",
        severity="LOW",
    )

    result = await enrich_with_providers(
        indicator,
        providers=[
            EmptyProvider(),
            SuccessfulProvider(),
        ],
    )

    assert result is not None
    assert result.value == "203.0.113.30"
    assert result.source == "SuccessfulProvider"


@pytest.mark.asyncio
async def test_all_failed_providers_return_original_indicator():
    indicator = ThreatIndicator(
        value="203.0.113.40",
        type="IP",
        source="OriginalSource",
        severity="MEDIUM",
    )

    result = await enrich_with_providers(
        indicator,
        providers=[
            FailingProvider(),
            EmptyProvider(),
        ],
    )

    assert result is not None

    assert result.value == "203.0.113.40"
    assert result.type == "IP"
    assert result.source == "OriginalSource"
    assert result.severity == "MEDIUM"


@pytest.mark.asyncio
async def test_enrichment_preserves_indicator_value():
    indicator = ThreatIndicator(
        value="example.com",
        type="DOMAIN",
        source="Manual",
        severity="LOW",
    )

    result = await enrich_with_providers(
        indicator,
        providers=[
            SuccessfulProvider(),
        ],
    )

    assert result.value == "example.com"
    assert result.type == "DOMAIN"