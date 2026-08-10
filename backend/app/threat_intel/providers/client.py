import httpx


class ThreatProviderClient:
    """
    Shared asynchronous HTTP client for
    external threat intelligence providers.
    """

    def __init__(
        self,
        api_key: str,
        timeout: float = 20.0,
    ):
        self.api_key = api_key
        self.timeout = timeout

    async def get(
        self,
        url: str,
        headers: dict | None = None,
        params: dict | None = None,
    ) -> dict:
        """
        Perform an asynchronous GET request.

        Raises:
            ValueError:
                When the provider API key is missing.
            httpx.HTTPError:
                When the HTTP request fails.
            ValueError:
                When the response body is not valid JSON.
        """

        if not self.api_key:
            raise ValueError(
                "Provider API key is not configured."
            )

        request_headers = headers or {}

        timeout = httpx.Timeout(
            self.timeout,
            connect=self.timeout,
        )

        async with httpx.AsyncClient(
            timeout=timeout,
        ) as client:
            response = await client.get(
                url,
                headers=request_headers,
                params=params,
            )

            response.raise_for_status()

            data = response.json()

            if not isinstance(data, dict):
                raise ValueError(
                    "Provider response must be a JSON object."
                )

            return data