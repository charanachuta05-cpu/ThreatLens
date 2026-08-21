import pytest

from app.threat_intel.enrichment_service import (
    enrich_with_providers,
)
from app.threat_intel.schemas import ThreatIndicator


class SuccessfulProvider:
    provider_name = "TestProvider"

    async def get_indicator_report(
        self,
        indicator_type: str,
        value: str,
    ):
        return ThreatIndicator(
            value=value,
            type=indicator_type,
            source="TestProvider",
            severity="HIGH",
            malicious=4,
            suspicious=1,
        )


class FailingProvider:
    provider_name = "FailingProvider"

    async def get_indicator_report(
        self,
        indicator_type: str,
        value: str,
    ):
        raise RuntimeError("Provider unavailable")


class EmptyProvider:
    provider_name = "EmptyProvider"

    async def get_indicator_report(
        self,
        indicator_type: str,
        value: str,
    ):
        return None

class MalformedProvider:
    provider_name = "MalformedProvider"

    async def get_indicator_report(
        self,
        indicator_type: str,
        value: str,
    ):
        raise KeyError("Malformed provider response")


@pytest.mark.asyncio
async def test_malformed_provider_response_preserves_original_indicator():
    indicator = ThreatIndicator(
        value="8.8.8.8",
        type="IP",
        source="Simulated",
        severity="LOW",
    )

    enriched = await enrich_with_providers(
        indicator,
        [MalformedProvider()],
    )

    assert enriched.value == "8.8.8.8"
    assert enriched.type == "IP"
    assert enriched.source == "Simulated"
    assert enriched.severity == "LOW"
    assert enriched.malicious == 0
    assert enriched.suspicious == 0


@pytest.mark.asyncio
async def test_provider_enrichment_updates_indicator():
    indicator = ThreatIndicator(
        value="8.8.8.8",
        type="IP",
        source="Simulated",
        severity="LOW",
    )

    enriched = await enrich_with_providers(
        indicator,
        [SuccessfulProvider()],
    )

    assert enriched.value == "8.8.8.8"
    assert enriched.type == "IP"
    assert enriched.source == "TestProvider"
    assert enriched.severity == "HIGH"
    assert enriched.malicious == 4
    assert enriched.suspicious == 1


@pytest.mark.asyncio
async def test_failed_provider_falls_back_to_next_provider():
    indicator = ThreatIndicator(
        value="8.8.4.4",
        type="IP",
        source="Simulated",
        severity="LOW",
    )

    enriched = await enrich_with_providers(
        indicator,
        [
            FailingProvider(),
            SuccessfulProvider(),
        ],
    )

    assert enriched.source == "TestProvider"
    assert enriched.severity == "HIGH"
    assert enriched.malicious == 4

@pytest.mark.asyncio
async def test_provider_failure_does_not_log_raw_exception(
    caplog,
):
    indicator = ThreatIndicator(
        value="8.8.8.8",
        type="IP",
        source="Simulated",
        severity="LOW",
    )

    class SensitiveFailingProvider:
        provider_name = "SensitiveFailingProvider"

        async def get_indicator_report(
            self,
            indicator_type: str,
            value: str,
        ):
            raise RuntimeError(
                "SECRET_PROVIDER_DETAILS"
            )

    with caplog.at_level("ERROR"):
        enriched = await enrich_with_providers(
            indicator,
            [SensitiveFailingProvider()],
        )

    assert enriched == indicator
    assert "SensitiveFailingProvider enrichment failed" in caplog.text
    assert "SECRET_PROVIDER_DETAILS" not in caplog.text


@pytest.mark.asyncio
async def test_empty_provider_falls_back_to_next_provider():
    indicator = ThreatIndicator(
        value="1.1.1.1",
        type="IP",
        source="Simulated",
        severity="LOW",
    )

    enriched = await enrich_with_providers(
        indicator,
        [
            EmptyProvider(),
            SuccessfulProvider(),
        ],
    )

    assert enriched.source == "TestProvider"
    assert enriched.severity == "HIGH"
    assert enriched.malicious == 4
    assert enriched.suspicious == 1


@pytest.mark.asyncio
async def test_all_provider_failures_preserve_original_indicator():
    indicator = ThreatIndicator(
        value="192.168.1.10",
        type="IP",
        source="Simulated",
        severity="LOW",
    )

    enriched = await enrich_with_providers(
        indicator,
        [
            FailingProvider(),
            EmptyProvider(),
        ],
    )

    assert enriched.value == indicator.value
    assert enriched.type == indicator.type
    assert enriched.source == indicator.source
    assert enriched.severity == indicator.severity
    assert enriched.malicious == indicator.malicious
    assert enriched.suspicious == indicator.suspicious


@pytest.mark.asyncio
async def test_provider_enrichment_preserves_indicator_type_and_value():
    indicator = ThreatIndicator(
        value="example.com",
        type="DOMAIN",
        source="Simulated",
        severity="LOW",
    )

    enriched = await enrich_with_providers(
        indicator,
        [SuccessfulProvider()],
    )

    assert enriched.value == "example.com"
    assert enriched.type == "DOMAIN"