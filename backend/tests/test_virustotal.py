import pytest

from app.threat_intel.providers.virustotal import VirusTotalProvider


def make_provider(monkeypatch, response_data):
    provider = VirusTotalProvider("test-api-key")

    async def mock_get(
        url,
        headers=None,
        params=None,
    ):
        return response_data

    monkeypatch.setattr(
        provider.client,
        "get",
        mock_get,
    )

    return provider


@pytest.mark.asyncio
async def test_get_ip_report_normalizes_malicious_ip(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "8.8.8.8",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 20,
                    "suspicious": 2,
                    "harmless": 60,
                },
                "reputation": 85,
                "tags": [
                    "dns",
                    "google",
                ],
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_ip_report(
        "8.8.8.8"
    )

    assert result.value == "8.8.8.8"
    assert result.type == "IP"
    assert result.source == "VirusTotal"
    assert result.severity == "CRITICAL"

    assert result.reputation == 85
    assert result.malicious == 20
    assert result.suspicious == 2
    assert result.harmless == 60

    assert result.tags == [
        "dns",
        "google",
    ]


@pytest.mark.asyncio
async def test_get_ip_report_high_severity(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "1.2.3.4",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 7,
                    "suspicious": 1,
                    "harmless": 50,
                },
                "reputation": 70,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_ip_report(
        "1.2.3.4"
    )

    assert result.severity == "HIGH"
    assert result.malicious == 7
    assert result.suspicious == 1


@pytest.mark.asyncio
async def test_get_ip_report_medium_severity(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "5.6.7.8",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 1,
                    "suspicious": 1,
                    "harmless": 70,
                },
                "reputation": 40,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_ip_report(
        "5.6.7.8"
    )

    assert result.severity == "MEDIUM"


@pytest.mark.asyncio
async def test_get_ip_report_low_severity(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "9.9.9.9",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 80,
                },
                "reputation": 0,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_ip_report(
        "9.9.9.9"
    )

    assert result.severity == "LOW"
    assert result.malicious == 0
    assert result.suspicious == 0


@pytest.mark.asyncio
async def test_reputation_is_capped_at_100(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "10.10.10.10",
            "attributes": {
                "last_analysis_stats": {},
                "reputation": 150,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_ip_report(
        "10.10.10.10"
    )

    assert result.reputation == 100


@pytest.mark.asyncio
async def test_missing_analysis_stats_use_defaults(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "11.11.11.11",
            "attributes": {
                "reputation": 25,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_ip_report(
        "11.11.11.11"
    )

    assert result.severity == "LOW"
    assert result.malicious == 0
    assert result.suspicious == 0
    assert result.harmless == 0
    assert result.reputation == 25


@pytest.mark.asyncio
async def test_collect_indicators_returns_empty_list(
    monkeypatch,
):
    provider = VirusTotalProvider(
        "test-api-key"
    )

    result = await provider.collect_indicators()

    assert result == []


@pytest.mark.asyncio
async def test_virustotal_indicator_integrates_with_enrichment(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "203.0.113.50",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 6,
                    "suspicious": 2,
                    "harmless": 70,
                },
                "reputation": 80,
                "tags": [
                    "malware",
                    "network",
                ],
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    indicator = await provider.get_ip_report(
        "203.0.113.50"
    )

    from app.threat_intel.enrichment import enrich_indicator

    enriched = enrich_indicator(indicator)

    assert indicator.source == "VirusTotal"

    assert indicator.malicious == 6
    assert indicator.suspicious == 2
    assert indicator.reputation == 80

    assert enriched.threat_score == 85

    # 6 malicious × 20 = 120
    # 2 suspicious × 10 = 20
    # capped at 100
    assert enriched.reputation_score == 100

    assert 0 <= enriched.confidence_score <= 100

    assert "malware" in enriched.tags
    assert "network" in enriched.tags


@pytest.mark.asyncio
async def test_get_domain_report(monkeypatch):
    response_data = {
        "data": {
            "id": "example.com",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 6,
                    "suspicious": 1,
                    "harmless": 70,
                },
                "reputation": 75,
                "tags": [
                    "domain",
                    "test",
                ],
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_domain_report(
        "example.com"
    )

    assert result.value == "example.com"
    assert result.type == "DOMAIN"
    assert result.source == "VirusTotal"
    assert result.severity == "HIGH"
    assert result.reputation == 75
    assert result.malicious == 6
    assert result.suspicious == 1
    assert result.tags == [
        "domain",
        "test",
    ]


@pytest.mark.asyncio
async def test_get_hash_report(monkeypatch):
    response_data = {
        "data": {
            "id": "a" * 64,
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 60,
                },
                "reputation": 50,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_hash_report(
        "a" * 64
    )

    assert result.type == "HASH"
    assert result.source == "VirusTotal"
    assert result.severity == "MEDIUM"
    assert result.malicious == 2

@pytest.mark.asyncio
async def test_get_url_report_normalizes_response(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "url-object-id",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 3,
                    "suspicious": 2,
                    "harmless": 60,
                },
                "reputation": 65,
                "tags": [
                    "phishing",
                    "malware",
                ],
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_url_report(
        "url-object-id"
    )

    assert result.value == "url-object-id"
    assert result.type == "URL"
    assert result.source == "VirusTotal"
    assert result.severity == "MEDIUM"
    assert result.reputation == 65
    assert result.malicious == 3
    assert result.suspicious == 2
    assert result.harmless == 60
    assert result.tags == [
        "phishing",
        "malware",
    ]


@pytest.mark.asyncio
async def test_reputation_is_clamped_at_zero(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "12.12.12.12",
            "attributes": {
                "last_analysis_stats": {},
                "reputation": -25,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_ip_report(
        "12.12.12.12"
    )

    assert result.reputation == 0


@pytest.mark.asyncio
async def test_tags_default_to_empty_list(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "13.13.13.13",
            "attributes": {
                "last_analysis_stats": {},
                "reputation": 10,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_ip_report(
        "13.13.13.13"
    )

    assert result.tags == []


@pytest.mark.asyncio
async def test_generic_indicator_report_routes_to_url(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "url-object-id",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 1,
                    "harmless": 70,
                },
                "reputation": 55,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_indicator_report(
        "url",
        "url-object-id",
    )

    assert result.type == "URL"
    assert result.value == "url-object-id"
    assert result.severity == "MEDIUM"

@pytest.mark.asyncio
async def test_get_ip_report_builds_expected_request(
    monkeypatch,
):
    provider = VirusTotalProvider(
        "test-api-key"
    )

    captured = {}

    async def mock_get(
        url,
        headers=None,
        params=None,
    ):
        captured["url"] = url
        captured["headers"] = headers
        captured["params"] = params

        return {
            "data": {
                "id": "8.8.8.8",
                "attributes": {
                    "last_analysis_stats": {},
                    "reputation": 20,
                },
            }
        }

    monkeypatch.setattr(
        provider.client,
        "get",
        mock_get,
    )

    await provider.get_ip_report(
        "8.8.8.8"
    )

    assert captured["url"] == (
        "https://www.virustotal.com/api/v3"
        "/ip_addresses/8.8.8.8"
    )

    assert captured["headers"] == {
        "x-apikey": "test-api-key"
    }

    assert captured["params"] is None


@pytest.mark.asyncio
async def test_generic_indicator_report_routes_to_ip(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "203.0.113.50",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "suspicious": 0,
                    "harmless": 50,
                },
                "reputation": 80,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    result = await provider.get_indicator_report(
        "ip",
        "203.0.113.50",
    )

    assert result.type == "IP"
    assert result.value == "203.0.113.50"
    assert result.severity == "HIGH"


@pytest.mark.asyncio
async def test_generic_indicator_report_rejects_unknown_type():
    provider = VirusTotalProvider(
        "test-api-key"
    )

    with pytest.raises(
        ValueError,
        match="Unsupported indicator type",
    ):
        await provider.get_indicator_report(
            "EMAIL",
            "test@example.com",
        )

@pytest.mark.asyncio
async def test_malformed_attributes_raise_provider_error(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "8.8.8.8",
            "attributes": None,
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    with pytest.raises(
        AttributeError,
    ):
        await provider.get_ip_report(
            "8.8.8.8"
        )


@pytest.mark.asyncio
async def test_malformed_analysis_stats_raise_provider_error(
    monkeypatch,
):
    response_data = {
        "data": {
            "id": "8.8.8.8",
            "attributes": {
                "last_analysis_stats": None,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    with pytest.raises(
        AttributeError,
    ):
        await provider.get_ip_report(
            "8.8.8.8"
        )


@pytest.mark.asyncio
async def test_missing_indicator_id_raises_provider_error(
    monkeypatch,
):
    response_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {},
                "reputation": 20,
            },
        }
    }

    provider = make_provider(
        monkeypatch,
        response_data,
    )

    with pytest.raises(
        KeyError,
    ):
        await provider.get_ip_report(
            "8.8.8.8"
        )