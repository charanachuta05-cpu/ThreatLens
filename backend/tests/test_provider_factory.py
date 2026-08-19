from app.threat_intel.providers.factory import (
    get_providers,
)
from app.threat_intel.providers.simulated import (
    SimulatedThreatProvider,
)
from app.threat_intel.providers.virustotal import (
    VirusTotalProvider,
)


def test_simulated_provider_is_enabled_by_default():
    providers = get_providers()

    assert any(
        isinstance(
            provider,
            SimulatedThreatProvider,
        )
        for provider in providers
    )


def test_virustotal_provider_is_enabled_with_api_key(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.threat_intel.providers.factory.settings.VIRUSTOTAL_ENABLED",
        True,
    )

    monkeypatch.setattr(
        "app.threat_intel.providers.factory.settings.VIRUSTOTAL_API_KEY",
        "test-api-key",
    )

    providers = get_providers()

    assert any(
        isinstance(
            provider,
            VirusTotalProvider,
        )
        for provider in providers
    )


def test_virustotal_provider_is_not_registered_without_api_key(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.threat_intel.providers.factory.settings.VIRUSTOTAL_ENABLED",
        True,
    )

    monkeypatch.setattr(
        "app.threat_intel.providers.factory.settings.VIRUSTOTAL_API_KEY",
        "",
    )

    providers = get_providers()

    assert not any(
        isinstance(
            provider,
            VirusTotalProvider,
        )
        for provider in providers
    )


def test_virustotal_provider_is_not_registered_when_disabled(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.threat_intel.providers.factory.settings.VIRUSTOTAL_ENABLED",
        False,
    )

    monkeypatch.setattr(
        "app.threat_intel.providers.factory.settings.VIRUSTOTAL_API_KEY",
        "test-api-key",
    )

    providers = get_providers()

    assert not any(
        isinstance(
            provider,
            VirusTotalProvider,
        )
        for provider in providers
    )


def test_virustotal_provider_uses_configured_timeout(
    monkeypatch,
):
    monkeypatch.setattr(
        "app.threat_intel.providers.factory.settings.VIRUSTOTAL_ENABLED",
        True,
    )

    monkeypatch.setattr(
        "app.threat_intel.providers.factory.settings.VIRUSTOTAL_API_KEY",
        "test-api-key",
    )

    monkeypatch.setattr(
        "app.threat_intel.providers.factory.settings.THREAT_PROVIDER_TIMEOUT",
        7.5,
    )

    providers = get_providers()

    virustotal = next(
        provider
        for provider in providers
        if isinstance(provider, VirusTotalProvider)
    )

    assert virustotal.client.timeout == 7.5
