import httpx
import pytest

from app.threat_intel.providers.client import (
    ThreatProviderClient,
    ThreatProviderClientError,
)

@pytest.mark.asyncio
async def test_client_converts_http_error_to_safe_provider_error(
    monkeypatch,
):
    class FakeResponse:
        def raise_for_status(self):
            request = httpx.Request(
                "GET",
                "https://example.com",
            )

            response = httpx.Response(
                404,
                request=request,
            )

            raise httpx.HTTPStatusError(
                "404 Not Found: SECRET_PROVIDER_DETAILS",
                request=request,
                response=response,
            )

        def json(self):
            return {}

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(
            self,
            exc_type,
            exc_value,
            traceback,
        ):
            pass

        async def get(
            self,
            url,
            headers=None,
            params=None,
        ):
            return FakeResponse()

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        FakeAsyncClient,
    )

    client = ThreatProviderClient(
        api_key="test-key"
    )

    with pytest.raises(
        ThreatProviderClientError,
        match="Threat intelligence provider request failed.",
    ) as exc_info:
        await client.get(
            "https://example.com"
        )

    assert "SECRET_PROVIDER_DETAILS" not in str(
        exc_info.value
    )

@pytest.mark.asyncio
async def test_client_rejects_non_object_json_response(
    monkeypatch,
):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return ["unexpected", "response"]

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(
            self,
            exc_type,
            exc_value,
            traceback,
        ):
            pass

        async def get(
            self,
            url,
            headers=None,
            params=None,
        ):
            return FakeResponse()

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        FakeAsyncClient,
    )

    client = ThreatProviderClient(
        api_key="test-key"
    )

    with pytest.raises(
        ThreatProviderClientError,
        match="Threat intelligence provider returned "
        "an invalid response.",
    ):
        await client.get(
            "https://example.com"
        )


@pytest.mark.asyncio
async def test_client_rejects_missing_api_key():
    client = ThreatProviderClient(
        api_key=""
    )

    with pytest.raises(
        ValueError,
        match="Provider API key is not configured.",
    ):
        await client.get(
            "https://example.com"
        )


@pytest.mark.asyncio
async def test_client_returns_json(monkeypatch):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {
                "status": "ok",
                "data": [],
            }

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(
            self,
            exc_type,
            exc_value,
            traceback,
        ):
            pass

        async def get(
            self,
            url,
            headers=None,
            params=None,
        ):
            assert url == "https://example.com"
            assert headers == {
                "x-api-key": "test-key"
            }
            assert params == {
                "page": 1
            }

            return FakeResponse()

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        FakeAsyncClient,
    )

    client = ThreatProviderClient(
        api_key="test-key"
    )

    result = await client.get(
        "https://example.com",
        headers={
            "x-api-key": "test-key"
        },
        params={
            "page": 1
        },
    )

    assert result == {
        "status": "ok",
        "data": [],
    }


@pytest.mark.asyncio
async def test_client_converts_http_error_to_safe_provider_error(
    monkeypatch,
):
    class FakeResponse:
        def raise_for_status(self):
            request = httpx.Request(
                "GET",
                "https://example.com",
            )

            response = httpx.Response(
                404,
                request=request,
            )

            raise httpx.HTTPStatusError(
                "404 Not Found",
                request=request,
                response=response,
            )

        def json(self):
            return {}

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(
            self,
            exc_type,
            exc_value,
            traceback,
        ):
            pass

        async def get(
            self,
            url,
            headers=None,
            params=None,
        ):
            return FakeResponse()

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        FakeAsyncClient,
    )

    client = ThreatProviderClient(
        api_key="test-key"
    )

    with pytest.raises(
        ThreatProviderClientError,
        match="Threat intelligence provider request failed.",
    ):
        await client.get(
            "https://example.com"
        )


@pytest.mark.asyncio
async def test_client_uses_default_headers_when_none(
    monkeypatch,
):
    class FakeResponse:
        def raise_for_status(self):
            pass

        def json(self):
            return {"ok": True}

    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(
            self,
            exc_type,
            exc_value,
            traceback,
        ):
            pass

        async def get(
            self,
            url,
            headers=None,
            params=None,
        ):
            assert headers == {}
            assert params is None

            return FakeResponse()

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        FakeAsyncClient,
    )

    client = ThreatProviderClient(
        api_key="test-key"
    )

    result = await client.get(
        "https://example.com"
    )

    assert result == {
        "ok": True
    }

@pytest.mark.asyncio
async def test_client_uses_configured_timeout(monkeypatch):
    captured = {}

    class FakeAsyncClient:
        def __init__(self, timeout):
            captured["timeout"] = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(
            self,
            exc_type,
            exc_value,
            traceback,
        ):
            pass

        async def get(
            self,
            url,
            headers=None,
            params=None,
        ):
            class FakeResponse:
                def raise_for_status(self):
                    pass

                def json(self):
                    return {"status": "ok"}

            return FakeResponse()

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        FakeAsyncClient,
    )

    client = ThreatProviderClient(
        api_key="test-key",
        timeout=7.5,
    )

    await client.get("https://example.com")

    timeout = captured["timeout"]

    assert timeout.connect == 7.5
    assert timeout.read == 7.5
    assert timeout.write == 7.5
    assert timeout.pool == 7.5

@pytest.mark.asyncio
async def test_client_converts_timeout_to_safe_provider_error(
    monkeypatch,
):
    class FakeAsyncClient:
        def __init__(self, timeout):
            self.timeout = timeout

        async def __aenter__(self):
            return self

        async def __aexit__(
            self,
            exc_type,
            exc_value,
            traceback,
        ):
            pass

        async def get(
            self,
            url,
            headers=None,
            params=None,
        ):
            request = httpx.Request(
                "GET",
                url,
            )

            raise httpx.ReadTimeout(
                "SECRET_PROVIDER_TIMEOUT_DETAILS",
                request=request,
            )

    monkeypatch.setattr(
        httpx,
        "AsyncClient",
        FakeAsyncClient,
    )

    client = ThreatProviderClient(
        api_key="test-key",
    )

    with pytest.raises(
        ThreatProviderClientError,
        match=(
            "Threat intelligence provider "
            "request timed out."
        ),
    ) as exc_info:
        await client.get(
            "https://example.com",
        )

    assert "SECRET_PROVIDER_TIMEOUT_DETAILS" not in str(
        exc_info.value
    )