import logging

logger = logging.getLogger(__name__)


class ThreatProviderManager:

    def __init__(self, providers):
        self.providers = providers

    async def collect_all(self):

        indicators = []

        for provider in self.providers:

            try:

                provider_results = await provider.collect_indicators()

                logger.info(
                    "%s returned %d indicators",
                    provider.provider_name,
                    len(provider_results),
                )

                indicators.extend(provider_results)

            except Exception as exc:

                logger.exception(
                    "%s provider failed: %s",
                    provider.provider_name,
                    exc,
                )

        return indicators