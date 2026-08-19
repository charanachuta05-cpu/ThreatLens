import httpx


class ThreatProviderClientError(Exception):
    """
    Safe application-level error raised when an external
    threat intelligence provider request fails.
    """


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

        Provider-specific HTTP failures are converted into a
        safe application-level exception so raw external
        response details cannot propagate beyond this boundary.
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

        try:
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

        except httpx.TimeoutException as exc:
            raise ThreatProviderClientError(
                "Threat intelligence provider request timed out."
            ) from exc

        except httpx.HTTPError as exc:
            raise ThreatProviderClientError(
                "Threat intelligence provider request failed."
            ) from exc

        except ValueError as exc:
            raise ThreatProviderClientError(
                "Threat intelligence provider returned "
                "an invalid response."
            ) from exc

        if not isinstance(data, dict):
            raise ThreatProviderClientError(
                "Threat intelligence provider returned "
                "an invalid response."
            )

        return data
