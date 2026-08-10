import logging

from app.threat_intel.schemas import ThreatIndicator

logger = logging.getLogger(__name__)


class ThreatProviderManager:
    """
    Coordinates multiple threat intelligence providers.

    A failure in one provider must never prevent the
    remaining providers from being processed.
    """

    def __init__(self, providers):
        self.providers = providers

    async def collect_all(self) -> list[ThreatIndicator]:
        """
        Collect indicators from every registered provider.

        Provider failures and malformed responses are isolated
        so that healthy providers can continue operating.
        """

        indicators: list[ThreatIndicator] = []

        for provider in self.providers:

            provider_name = getattr(
                provider,
                "provider_name",
                provider.__class__.__name__,
            )

            try:
                provider_results = (
                    await provider.collect_indicators()
                )

                if not provider_results:
                    logger.warning(
                        "%s provider returned no indicators",
                        provider_name,
                    )
                    continue

                if not isinstance(
                    provider_results,
                    list,
                ):
                    logger.warning(
                        "%s provider returned invalid "
                        "result type: %s",
                        provider_name,
                        type(provider_results).__name__,
                    )
                    continue

                valid_results = [
                    indicator
                    for indicator in provider_results
                    if isinstance(
                        indicator,
                        ThreatIndicator,
                    )
                ]

                skipped = (
                    len(provider_results)
                    - len(valid_results)
                )

                if skipped:
                    logger.warning(
                        "%s provider returned %d "
                        "invalid indicators",
                        provider_name,
                        skipped,
                    )

                logger.info(
                    "%s returned %d valid indicators",
                    provider_name,
                    len(valid_results),
                )

                indicators.extend(
                    valid_results
                )

            except Exception as exc:
                logger.exception(
                    "%s provider failed: %s",
                    provider_name,
                    exc,
                )

        return indicators